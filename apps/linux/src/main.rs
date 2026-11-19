//! Native GTK4 frontend for SuikaAuthenticator.
//!
//! The shared core owns vault and account cryptography. This binary owns only
//! GTK presentation and the Linux application-directory choice.

use std::cell::{Cell, RefCell};
use std::fs;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::mpsc::{self, TryRecvError};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use gdk_pixbuf::Pixbuf;
use gtk::gio;
use gtk::glib::{self, ControlFlow};
use gtk::prelude::*;
use gtk::{
    Align, Application, ApplicationWindow, Box as GtkBox, Button, Entry, Label, ListBox,
    ListBoxRow, Orientation, ScrolledWindow, Spinner, Stack,
};
use suika_core::accounts::{Account, AccountDatabase, AccountMode};
use suika_core::base32::decode_base32;
use suika_core::crypto::KdfParams;
use suika_core::otp::OtpAlgorithm;
use suika_core::otpauth::{OtpAuthError, parse_otpauth_uri};
use suika_core::storage::{StorageError, VaultStore};
use suika_core::vault::{Vault, VaultError, VaultSession};
use zeroize::Zeroizing;

const APP_ID: &str = "org.suika.SuikaAuthenticator";
const DATA_DIRECTORY: &str = ".SuikaAuthenticator";
const INACTIVITY_LOCK_TIMEOUT: Duration = Duration::from_secs(5 * 60);

thread_local! {
    static LAST_ACTIVITY: Cell<Instant> = Cell::new(Instant::now());
}

fn record_activity() {
    LAST_ACTIVITY.with(|last| last.set(Instant::now()));
}

fn inactivity_duration() -> Duration {
    LAST_ACTIVITY.with(|last| Instant::now().saturating_duration_since(last.get()))
}

struct AuthenticatedVault {
    // Kept alive for the complete unlocked session. Dropping this clears the
    // decrypted account database and the in-memory data-encryption key.
    session: VaultSession,
    accounts: AccountDatabase,
}

#[derive(Clone, Copy)]
enum AuthMode {
    Create,
    Unlock,
}

fn main() -> glib::ExitCode {
    std::panic::set_hook(Box::new(|_| {}));
    let application = Application::builder().application_id(APP_ID).build();
    application.connect_activate(build_application);
    application.run()
}

fn build_application(application: &Application) {
    let window = ApplicationWindow::builder()
        .application(application)
        .title("SuikaAuthenticator")
        .default_width(560)
        .default_height(680)
        .build();

    let unlocked = Rc::new(RefCell::new(None::<AuthenticatedVault>));
    install_activity_tracking(&window);

    let stack = Stack::new();
    stack.set_transition_type(gtk::StackTransitionType::Crossfade);
    window.set_child(Some(&stack));

    let stack_for_close = stack.clone();
    let unlocked_for_close = unlocked.clone();
    window.connect_close_request(move |_| {
        clear_secret_entries(stack_for_close.upcast_ref());
        unlocked_for_close.borrow_mut().take();
        glib::Propagation::Proceed
    });

    let stack_for_shutdown = stack.downgrade();
    let unlocked_for_shutdown = unlocked.clone();
    application.connect_shutdown(move |_| {
        if let Some(stack) = stack_for_shutdown.upgrade() {
            clear_secret_entries(stack.upcast_ref());
        }
        unlocked_for_shutdown.borrow_mut().take();
    });

    let directory = match application_directory() {
        Ok(directory) => directory,
        Err(error) => {
            show_startup_error(&stack, &error);
            window.present();
            return;
        }
    };

    let store = match VaultStore::open(&directory) {
        Ok(store) => store,
        Err(error) => {
            show_startup_error(&stack, &error.to_string());
            window.present();
            return;
        }
    };

    let mode = match store.load() {
        Ok(_) => AuthMode::Unlock,
        Err(StorageError::VaultNotFound) => AuthMode::Create,
        Err(error) => {
            show_startup_error(&stack, &error.to_string());
            window.present();
            return;
        }
    };

    let directory_for_timeout = directory.clone();
    show_auth_page(&stack, &window, directory, mode, unlocked.clone());
    start_inactivity_monitor(&window, &stack, directory_for_timeout, unlocked);
    window.present();
}

fn application_directory() -> Result<PathBuf, String> {
    let home = std::env::var_os("HOME")
        .ok_or_else(|| "The HOME environment variable is not available.".to_owned())?;
    let home = PathBuf::from(home);
    if !home.is_absolute() {
        return Err("The HOME environment variable must contain an absolute path.".to_owned());
    }
    Ok(home.join(DATA_DIRECTORY))
}

fn clear_secret_entries(widget: &gtk::Widget) {
    if widget.widget_name() == "suika-secret-entry"
        && let Ok(entry) = widget.clone().downcast::<Entry>()
    {
        entry.set_text("");
    }

    let mut child = widget.first_child();
    while let Some(current) = child {
        clear_secret_entries(&current);
        child = current.next_sibling();
    }
}

fn install_activity_tracking(window: &ApplicationWindow) {
    let motion = gtk::EventControllerMotion::new();
    motion.set_propagation_phase(gtk::PropagationPhase::Capture);
    motion.connect_motion(|_, _, _| record_activity());
    window.add_controller(motion);

    let click = gtk::GestureClick::new();
    click.set_propagation_phase(gtk::PropagationPhase::Capture);
    click.connect_pressed(|_, _, _, _| record_activity());
    window.add_controller(click);

    let key = gtk::EventControllerKey::new();
    key.set_propagation_phase(gtk::PropagationPhase::Capture);
    key.connect_key_pressed(|_, _, _, _| {
        record_activity();
        glib::Propagation::Proceed
    });
    window.add_controller(key);

    let scroll = gtk::EventControllerScroll::new(gtk::EventControllerScrollFlags::BOTH_AXES);
    scroll.set_propagation_phase(gtk::PropagationPhase::Capture);
    scroll.connect_scroll(|_, _, _| {
        record_activity();
        glib::Propagation::Proceed
    });
    window.add_controller(scroll);
}

fn lock_vault_to_auth(
    stack: &Stack,
    window: &ApplicationWindow,
    directory: PathBuf,
    unlocked: Rc<RefCell<Option<AuthenticatedVault>>>,
) {
    clear_secret_entries(stack.upcast_ref());
    unlocked.borrow_mut().take();
    for name in ["accounts", "add-account", "edit-account"] {
        if let Some(page) = stack.child_by_name(name) {
            stack.remove(&page);
        }
    }
    record_activity();
    show_auth_page(stack, window, directory, AuthMode::Unlock, unlocked);
}

fn start_inactivity_monitor(
    window: &ApplicationWindow,
    stack: &Stack,
    directory: PathBuf,
    unlocked: Rc<RefCell<Option<AuthenticatedVault>>>,
) {
    let stack_weak = stack.downgrade();
    let window_weak = window.downgrade();

    glib::source::timeout_add_seconds_local(1, move || {
        if window_weak.upgrade().is_none() {
            unlocked.borrow_mut().take();
            return ControlFlow::Break;
        }

        let should_lock =
            unlocked.borrow().is_some() && inactivity_duration() >= INACTIVITY_LOCK_TIMEOUT;
        if should_lock {
            if let (Some(stack), Some(window)) = (stack_weak.upgrade(), window_weak.upgrade()) {
                lock_vault_to_auth(&stack, &window, directory.clone(), unlocked.clone());
            } else {
                unlocked.borrow_mut().take();
                return ControlFlow::Break;
            }
        }

        ControlFlow::Continue
    });
}

fn show_startup_error(stack: &Stack, message: &str) {
    let page = GtkBox::new(Orientation::Vertical, 12);
    page.set_margin_top(48);
    page.set_margin_bottom(48);
    page.set_margin_start(36);
    page.set_margin_end(36);
    page.set_valign(Align::Center);

    let title = Label::new(Some("Storage could not be opened"));
    title.add_css_class("title-1");
    title.set_xalign(0.0);

    let detail = Label::new(Some(message));
    detail.set_wrap(true);
    detail.set_xalign(0.0);

    let location = Label::new(Some(
        "SuikaAuthenticator uses one application directory: ~/.SuikaAuthenticator/",
    ));
    location.add_css_class("dim-label");
    location.set_wrap(true);
    location.set_xalign(0.0);

    page.append(&title);
    page.append(&detail);
    page.append(&location);
    replace_page(stack, "startup-error", &page);
}

fn show_auth_page(
    stack: &Stack,
    window: &ApplicationWindow,
    directory: PathBuf,
    mode: AuthMode,
    unlocked: Rc<RefCell<Option<AuthenticatedVault>>>,
) {
    let page = GtkBox::new(Orientation::Vertical, 18);
    page.set_margin_top(48);
    page.set_margin_bottom(48);
    page.set_margin_start(32);
    page.set_margin_end(32);
    page.set_halign(Align::Center);
    page.set_valign(Align::Center);

    let title = Label::new(Some("SuikaAuthenticator"));
    title.add_css_class("title-1");

    let subtitle = match mode {
        AuthMode::Create => "Create your encrypted vault",
        AuthMode::Unlock => "Unlock your encrypted vault",
    };
    let description = Label::new(Some(subtitle));
    description.add_css_class("dim-label");

    let card = GtkBox::new(Orientation::Vertical, 12);
    card.set_width_request(360);
    card.set_margin_top(12);

    let password = Entry::new();
    password.set_placeholder_text(Some("Master password"));
    password.set_visibility(false);
    password.set_input_purpose(gtk::InputPurpose::Password);
    password.set_max_length(1024);
    password.set_hexpand(true);

    let confirm = Entry::new();
    if matches!(mode, AuthMode::Create) {
        confirm.set_placeholder_text(Some("Confirm master password"));
        confirm.set_visibility(false);
        confirm.set_input_purpose(gtk::InputPurpose::Password);
        confirm.set_max_length(1024);
        confirm.set_hexpand(true);
    }

    let hint = Label::new(Some(
        "Use a long, unique passphrase. This password is required to recover your vault.",
    ));
    hint.set_wrap(true);
    hint.set_xalign(0.0);
    hint.add_css_class("dim-label");

    let status = Label::new(None);
    status.set_wrap(true);
    status.set_xalign(0.0);

    let spinner_row = GtkBox::new(Orientation::Horizontal, 8);
    let spinner = Spinner::new();
    let progress = Label::new(Some("Preparing encrypted vault…"));
    spinner_row.append(&spinner);
    spinner_row.append(&progress);
    spinner_row.set_visible(false);

    let action_text = match mode {
        AuthMode::Create => "Create encrypted vault",
        AuthMode::Unlock => "Unlock",
    };
    let action = Button::with_label(action_text);
    action.add_css_class("suggested-action");
    action.set_hexpand(true);

    card.append(&password);
    if matches!(mode, AuthMode::Create) {
        card.append(&confirm);
        card.append(&hint);
    }
    card.append(&action);
    card.append(&spinner_row);
    card.append(&status);

    page.append(&title);
    page.append(&description);
    page.append(&card);

    let stack_weak = stack.downgrade();
    let window_weak = window.downgrade();
    let directory_for_worker = directory.clone();
    let directory_for_home = directory.clone();
    let unlocked_for_action = unlocked.clone();
    let password_for_action = password.clone();
    let confirm_for_action = confirm.clone();
    let status_for_action = status.clone();
    let spinner_row_for_action = spinner_row.clone();
    let spinner_for_action = spinner.clone();
    let progress_for_action = progress.clone();

    action.connect_clicked(move |button| {
        let password_text = password_for_action.text().to_string();
        password_for_action.set_text("");
        let password_bytes = Zeroizing::new(password_text.into_bytes());

        let confirmation = if matches!(mode, AuthMode::Create) {
            let confirmation_text = confirm_for_action.text().to_string();
            confirm_for_action.set_text("");
            Some(Zeroizing::new(confirmation_text.into_bytes()))
        } else {
            None
        };

        if password_bytes.is_empty() {
            status_for_action.set_text("Enter your master password.");
            return;
        }
        if password_bytes.len() > 1024 {
            status_for_action
                .set_text("The password is longer than the supported 1024-byte limit.");
            return;
        }
        if confirmation
            .as_ref()
            .is_some_and(|value| password_bytes.as_slice() != value.as_slice())
        {
            status_for_action.set_text("The passwords do not match. Enter them again.");
            return;
        }

        status_for_action.set_text("");
        status_for_action.remove_css_class("error");
        spinner_row_for_action.set_visible(true);
        spinner_for_action.start();
        progress_for_action.set_text(match mode {
            AuthMode::Create => "Deriving key and creating vault…",
            AuthMode::Unlock => "Deriving key and checking vault…",
        });
        button.set_sensitive(false);
        password_for_action.set_sensitive(false);
        confirm_for_action.set_sensitive(false);

        let action_weak = button.downgrade();
        let stack_weak = stack_weak.clone();
        let window_weak = window_weak.clone();
        let directory = directory_for_home.clone();
        let unlocked = unlocked_for_action.clone();
        let status = status_for_action.clone();
        let spinner_row = spinner_row_for_action.clone();
        let spinner = spinner_for_action.clone();
        let password_entry = password_for_action.clone();
        let confirm_entry = confirm_for_action.clone();

        run_auth_task(
            directory_for_worker.clone(),
            mode,
            password_bytes,
            move |result| {
                spinner.stop();
                spinner_row.set_visible(false);
                if let Some(action) = action_weak.upgrade() {
                    action.set_sensitive(true);
                }
                password_entry.set_sensitive(true);
                confirm_entry.set_sensitive(true);

                match result {
                    Ok(authenticated) => {
                        record_activity();
                        *unlocked.borrow_mut() = Some(authenticated);
                        if let (Some(stack), Some(window)) =
                            (stack_weak.upgrade(), window_weak.upgrade())
                        {
                            show_accounts_page(&stack, &window, directory, unlocked);
                        }
                    }
                    Err(message) => {
                        status.add_css_class("error");
                        status.set_text(&message);
                    }
                }
            },
        );
    });

    let action_weak = action.downgrade();
    password.connect_activate(move |_| {
        if let Some(action) = action_weak.upgrade() {
            action.emit_clicked();
        }
    });

    replace_page(stack, "auth", &page);
}

fn replace_page(stack: &Stack, name: &str, page: &impl IsA<gtk::Widget>) {
    if let Some(existing) = stack.child_by_name(name) {
        stack.remove(&existing);
    }
    stack.add_named(page, Some(name));
    stack.set_visible_child_name(name);
}

fn run_auth_task(
    directory: PathBuf,
    mode: AuthMode,
    password: Zeroizing<Vec<u8>>,
    completed: impl FnOnce(Result<AuthenticatedVault, String>) + 'static,
) {
    let (sender, receiver) = mpsc::sync_channel(1);
    let worker_name = match mode {
        AuthMode::Create => "suika-vault-create",
        AuthMode::Unlock => "suika-vault-unlock",
    };

    let worker = thread::Builder::new()
        .name(worker_name.to_owned())
        .spawn(move || {
            let result = authenticate(&directory, mode, password.as_slice());
            let _ = sender.send(result);
        });

    if let Err(error) = worker {
        completed(Err(format!("Could not start the vault worker: {error}")));
        return;
    }

    let mut completed = Some(completed);
    glib::source::timeout_add_local(Duration::from_millis(100), move || {
        match receiver.try_recv() {
            Ok(result) => {
                if let Some(callback) = completed.take() {
                    callback(result);
                }
                ControlFlow::Break
            }
            Err(TryRecvError::Empty) => ControlFlow::Continue,
            Err(TryRecvError::Disconnected) => {
                if let Some(callback) = completed.take() {
                    callback(Err("The vault worker stopped unexpectedly.".to_owned()));
                }
                ControlFlow::Break
            }
        }
    });
}

fn authenticate(
    directory: &Path,
    mode: AuthMode,
    password: &[u8],
) -> Result<AuthenticatedVault, String> {
    let store = VaultStore::open(directory).map_err(|error| error.to_string())?;

    match mode {
        AuthMode::Create => {
            match store.load() {
                Err(StorageError::VaultNotFound) => {}
                Ok(_) => {
                    return Err(
                        "A vault already exists in this directory. Close and reopen the application to unlock it."
                            .to_owned(),
                    );
                }
                Err(error) => return Err(error.to_string()),
            }

            let database = AccountDatabase::new();
            let plaintext = database.encode().map_err(|error| error.to_string())?;
            let (serialized, session) =
                Vault::create_session(plaintext.as_slice(), password, KdfParams::PRODUCTION)
                    .map_err(|error: VaultError| error.to_string())?;
            store
                .save_new(&serialized)
                .map_err(|error| error.to_string())?;

            Ok(AuthenticatedVault {
                session,
                accounts: database,
            })
        }
        AuthMode::Unlock => {
            let serialized = store.load().map_err(|error| error.to_string())?;
            let session =
                Vault::unlock(&serialized, password).map_err(|error| error.to_string())?;
            let database =
                AccountDatabase::decode(session.plaintext()).map_err(|error| error.to_string())?;

            Ok(AuthenticatedVault {
                session,
                accounts: database,
            })
        }
    }
}

fn labeled_entry_field(parent: &GtkBox, label_text: &str, placeholder: &str) -> (GtkBox, Entry) {
    let field = GtkBox::new(Orientation::Vertical, 4);
    let label = Label::new(Some(label_text));
    label.set_xalign(0.0);
    label.add_css_class("heading");

    let entry = Entry::new();
    entry.set_placeholder_text(Some(placeholder));
    entry.set_hexpand(true);

    field.append(&label);
    field.append(&entry);
    parent.append(&field);
    (field, entry)
}

fn labeled_entry(parent: &GtkBox, label_text: &str, placeholder: &str) -> Entry {
    labeled_entry_field(parent, label_text, placeholder).1
}

fn labeled_dropdown(
    parent: &GtkBox,
    label_text: &str,
    options: &[&str],
    selected: u32,
) -> (gtk::DropDown, GtkBox) {
    let field = GtkBox::new(Orientation::Vertical, 4);
    let label = Label::new(Some(label_text));
    label.set_xalign(0.0);
    label.add_css_class("heading");

    let dropdown = gtk::DropDown::from_strings(options);
    dropdown.set_selected(selected);
    dropdown.set_hexpand(true);

    field.append(&label);
    field.append(&dropdown);
    parent.append(&field);
    (dropdown, field)
}

const TOTP_PERIOD_PRESETS: [u64; 7] = [15, 30, 45, 60, 90, 120, 300];
const HOTP_COUNTER_PRESETS: [u64; 6] = [0, 1, 2, 5, 10, 100];

fn selected_parameter(
    mode_selected: u32,
    period_selected: u32,
    counter_selected: u32,
    custom_value: &str,
) -> Result<u64, &'static str> {
    match mode_selected {
        0 if period_selected == TOTP_PERIOD_PRESETS.len() as u32 => custom_value
            .trim()
            .parse::<u64>()
            .map_err(|_| "Enter a valid custom TOTP period in seconds."),
        0 => TOTP_PERIOD_PRESETS
            .get(period_selected as usize)
            .copied()
            .ok_or("Choose a TOTP period."),
        1 if counter_selected == HOTP_COUNTER_PRESETS.len() as u32 => custom_value
            .trim()
            .parse::<u64>()
            .map_err(|_| "Enter a valid custom HOTP counter."),
        1 => HOTP_COUNTER_PRESETS
            .get(counter_selected as usize)
            .copied()
            .ok_or("Choose an HOTP counter."),
        _ => Err("Choose TOTP or HOTP as the OTP mode."),
    }
}

fn bind_parameter_fields(
    mode: &gtk::DropDown,
    period: &gtk::DropDown,
    period_field: &GtkBox,
    counter: &gtk::DropDown,
    counter_field: &GtkBox,
    custom_field: &GtkBox,
) {
    let mode_for_update = mode.clone();
    let period_for_update = period.clone();
    let counter_for_update = counter.clone();
    let period_field = period_field.clone();
    let counter_field = counter_field.clone();
    let custom_field = custom_field.clone();
    let update = Rc::new(move || {
        let is_totp = mode_for_update.selected() == 0;
        period_field.set_visible(is_totp);
        counter_field.set_visible(!is_totp);
        let custom_selected = if is_totp {
            period_for_update.selected() == TOTP_PERIOD_PRESETS.len() as u32
        } else {
            counter_for_update.selected() == HOTP_COUNTER_PRESETS.len() as u32
        };
        custom_field.set_visible(custom_selected);
    });
    let update_mode = update.clone();
    mode.connect_selected_notify(move |_| update_mode());
    let update_period = update.clone();
    period.connect_selected_notify(move |_| update_period());
    let update_counter = update.clone();
    counter.connect_selected_notify(move |_| update_counter());
    update();
}

fn show_add_account_page(
    stack: &Stack,
    window: &ApplicationWindow,
    directory: PathBuf,
    unlocked: Rc<RefCell<Option<AuthenticatedVault>>>,
) {
    let page = GtkBox::new(Orientation::Vertical, 14);
    page.set_margin_top(28);
    page.set_margin_bottom(28);
    page.set_margin_start(28);
    page.set_margin_end(28);

    let title = Label::new(Some("Add an account"));
    title.add_css_class("title-1");
    title.set_xalign(0.0);

    let description = Label::new(Some(
        "Paste an otpauth:// provisioning URI or enter the details manually. Imported parameters are validated and the secret is encrypted before saving.",
    ));
    description.set_wrap(true);
    description.set_xalign(0.0);
    description.add_css_class("dim-label");

    let import_qr = Button::with_label("Import QR image");
    let provisioning_uri = labeled_entry(
        &page,
        "Provisioning URI (optional)",
        "otpauth://totp/Issuer:account?secret=…",
    );
    provisioning_uri.set_visibility(false);
    provisioning_uri.set_input_purpose(gtk::InputPurpose::Password);
    provisioning_uri.set_widget_name("suika-secret-entry");
    provisioning_uri.set_max_length(4096);
    page.append(&import_qr);

    let issuer = labeled_entry(&page, "Issuer (optional)", "Example: GitHub");
    issuer.set_max_length(256);

    let label = labeled_entry(&page, "Account name", "Example: name@example.com");
    label.set_max_length(256);

    let secret = labeled_entry(&page, "TOTP secret (Base32)", "Paste the secret key");
    secret.set_visibility(false);
    secret.set_input_purpose(gtk::InputPurpose::Password);
    secret.set_widget_name("suika-secret-entry");
    secret.set_max_length(208);

    let (mode, _mode_field) = labeled_dropdown(&page, "OTP mode", &["TOTP", "HOTP"], 0);
    let (algorithm, _algorithm_field) =
        labeled_dropdown(&page, "HMAC algorithm", &["SHA1", "SHA256", "SHA512"], 0);
    let (digits, _digits_field) = labeled_dropdown(&page, "Code digits", &["6", "7", "8"], 0);
    let (period, period_field) = labeled_dropdown(
        &page,
        "TOTP period",
        &[
            "15 seconds",
            "30 seconds",
            "45 seconds",
            "60 seconds",
            "90 seconds",
            "120 seconds",
            "300 seconds",
            "Custom…",
        ],
        1,
    );
    let (counter, counter_field) = labeled_dropdown(
        &page,
        "HOTP initial counter",
        &["0", "1", "2", "5", "10", "100", "Custom…"],
        0,
    );
    let (custom_parameter_field, custom_parameter) = labeled_entry_field(
        &page,
        "Custom period (seconds) or counter",
        "Enter a positive period or counter value",
    );
    bind_parameter_fields(
        &mode,
        &period,
        &period_field,
        &counter,
        &counter_field,
        &custom_parameter_field,
    );

    let status = Label::new(None);
    status.set_wrap(true);
    status.set_xalign(0.0);

    let buttons = GtkBox::new(Orientation::Horizontal, 8);
    let back = Button::with_label("Cancel");
    let save = Button::with_label("Add account");
    save.add_css_class("suggested-action");
    save.set_hexpand(true);
    buttons.append(&back);
    buttons.append(&save);

    page.append(&title);
    page.append(&description);
    page.append(&status);
    page.append(&buttons);

    let stack_weak = stack.downgrade();
    let window_weak = window.downgrade();
    let directory_for_back = directory.clone();
    let unlocked_for_back = unlocked.clone();
    let secret_for_back = secret.clone();
    let uri_for_back = provisioning_uri.clone();
    back.connect_clicked(move |_| {
        secret_for_back.set_text("");
        uri_for_back.set_text("");
        if let (Some(stack), Some(window)) = (stack_weak.upgrade(), window_weak.upgrade()) {
            show_accounts_page(
                &stack,
                &window,
                directory_for_back.clone(),
                unlocked_for_back.clone(),
            );
        }
    });

    let directory_for_save = directory.clone();
    let unlocked_for_save = unlocked.clone();
    let stack_weak = stack.downgrade();
    let window_weak = window.downgrade();
    let issuer_for_save = issuer.clone();
    let label_for_save = label.clone();
    let secret_for_save = secret.clone();
    let uri_for_save = provisioning_uri.clone();
    let algorithm_for_save = algorithm.clone();
    let digits_for_save = digits.clone();
    let mode_for_save = mode.clone();
    let period_for_save = period.clone();
    let counter_for_save = counter.clone();
    let custom_parameter_for_save = custom_parameter.clone();
    let status_for_save = status.clone();
    let save_for_save = save.clone();

    let uri_for_qr = provisioning_uri.clone();
    let status_for_qr = status.clone();
    let window_for_qr = window.clone();
    import_qr.connect_clicked(move |_| {
        let file_dialog = gtk::FileDialog::builder()
            .title("Import authenticator QR image")
            .accept_label("Import")
            .modal(true)
            .build();
        let uri_field = uri_for_qr.clone();
        let status_label = status_for_qr.clone();
        file_dialog.open(
            Some(&window_for_qr),
            None::<&gio::Cancellable>,
            move |result| {
                let Ok(file) = result else {
                    return;
                };
                let Some(path) = file.path() else {
                    status_label.set_text("The selected image is not available as a local file.");
                    return;
                };
                match decode_otpauth_qr_image(&path) {
                    Ok(uri) => match parse_otpauth_uri(uri.as_str()) {
                        Ok(_) => {
                            uri_field.set_text(uri.as_str());
                            status_label.set_text(
                                "QR code decoded. Review the imported URI, then select Add account.",
                            );
                        }
                        Err(error) => {
                            status_label.set_text(&format!(
                                "The QR code does not contain a supported authenticator: {error}"
                            ));
                        }
                    },
                    Err(message) => status_label.set_text(&message),
                }
            },
        );
    });

    save.connect_clicked(move |_| {
        let uri_value = Zeroizing::new(uri_for_save.text().to_string());
        uri_for_save.set_text("");

        let account_result = if !uri_value.trim().is_empty() {
            secret_for_save.set_text("");
            parse_otpauth_uri(uri_value.trim())
        } else {
            let issuer_value = issuer_for_save.text().trim().to_owned();
            let label_value = label_for_save.text().trim().to_owned();
            let secret_value = Zeroizing::new(secret_for_save.text().to_string());
            secret_for_save.set_text("");

            let algorithm_value = match algorithm_for_save.selected() {
                0 => OtpAlgorithm::Sha1,
                1 => OtpAlgorithm::Sha256,
                2 => OtpAlgorithm::Sha512,
                _ => {
                    status_for_save.set_text("Choose SHA1, SHA256, or SHA512.");
                    return;
                }
            };
            let digits_value = match digits_for_save.selected() {
                value @ 0..=2 => (value + 6) as u8,
                _ => {
                    status_for_save.set_text("Choose a code length of 6, 7, or 8 digits.");
                    return;
                }
            };
            let mode_value = match mode_for_save.selected() {
                0 => "TOTP",
                1 => "HOTP",
                _ => {
                    status_for_save.set_text("Choose TOTP or HOTP as the OTP mode.");
                    return;
                }
            };
            let parameter_value = match selected_parameter(
                mode_for_save.selected(),
                period_for_save.selected(),
                counter_for_save.selected(),
                custom_parameter_for_save.text().as_str(),
            ) {
                Ok(value) => value,
                Err(message) => {
                    status_for_save.set_text(message);
                    return;
                }
            };
            if mode_value == "TOTP" && !(1..=86_400).contains(&parameter_value) {
                status_for_save.set_text("TOTP period must be between 1 and 86400 seconds.");
                return;
            }
            if label_value.is_empty() {
                status_for_save.set_text("Enter an account name.");
                return;
            }

            let secret_bytes = match decode_base32(secret_value.as_str()) {
                Ok(value) if value.len() >= 16 => value,
                Ok(_) => {
                    status_for_save.set_text("Use a secret containing at least 16 decoded bytes.");
                    return;
                }
                Err(message) => {
                    status_for_save.set_text(&message.to_string());
                    return;
                }
            };

            let created = if mode_value == "TOTP" {
                Account::new_totp(
                    issuer_value,
                    label_value,
                    secret_bytes,
                    algorithm_value,
                    digits_value,
                    parameter_value,
                )
            } else {
                Account::new_hotp(
                    issuer_value,
                    label_value,
                    secret_bytes,
                    algorithm_value,
                    digits_value,
                    parameter_value,
                )
            };
            created.map_err(OtpAuthError::from)
        };

        let account = match account_result {
            Ok(account) => account,
            Err(error) => {
                status_for_save.set_text(&error.to_string());
                return;
            }
        };

        save_for_save.set_sensitive(false);
        status_for_save.set_text("Encrypting and saving account…");

        let result = {
            let mut guard = unlocked_for_save.borrow_mut();
            match guard.as_mut() {
                Some(vault) => match vault.accounts.insert(account) {
                    Ok(()) => persist_vault(vault, &directory_for_save),
                    Err(error) => Err(error.to_string()),
                },
                None => Err("The vault is locked. Unlock it before adding an account.".to_owned()),
            }
        };

        save_for_save.set_sensitive(true);
        match result {
            Ok(()) => {
                if let (Some(stack), Some(window)) =
                    (stack_weak.upgrade(), window_weak.upgrade())
                {
                    show_accounts_page(
                        &stack,
                        &window,
                        directory_for_save.clone(),
                        unlocked_for_save.clone(),
                    );
                }
            }
            Err(message) => {
                status_for_save.set_text(&format!(
                    "The account remains in this unlocked session, but the disk save was not confirmed: {message}"
                ));
            }
        }
    });

    replace_page(stack, "add-account", &page);
}

fn decode_otpauth_qr_image(path: &Path) -> Result<Zeroizing<String>, String> {
    const MAX_IMAGE_FILE_BYTES: u64 = 32 * 1024 * 1024;
    const MAX_IMAGE_DIMENSION: usize = 2048;
    const MAX_URI_BYTES: usize = 4096;

    let metadata = fs::metadata(path).map_err(|_| "The selected image could not be opened.")?;
    if !metadata.is_file() || metadata.len() > MAX_IMAGE_FILE_BYTES {
        return Err("Choose an image file smaller than 32 MiB.".to_owned());
    }

    // GdkPixbuf handles the installed image formats; cap its output dimensions
    // before handing the buffer to the pure-Rust QR decoder.
    let pixbuf = Pixbuf::from_file_at_scale(
        path,
        MAX_IMAGE_DIMENSION as i32,
        MAX_IMAGE_DIMENSION as i32,
        true,
    )
    .map_err(|_| "The selected file is not a supported image.")?;

    let width = usize::try_from(pixbuf.width())
        .map_err(|_| "The selected image has invalid dimensions.")?;
    let height = usize::try_from(pixbuf.height())
        .map_err(|_| "The selected image has invalid dimensions.")?;
    let channels = usize::try_from(pixbuf.n_channels())
        .map_err(|_| "The selected image has an unsupported pixel format.")?;
    let bits_per_sample = pixbuf.bits_per_sample();
    let rowstride = usize::try_from(pixbuf.rowstride())
        .map_err(|_| "The selected image has invalid row data.")?;

    if width == 0
        || height == 0
        || width > MAX_IMAGE_DIMENSION
        || height > MAX_IMAGE_DIMENSION
        || channels < 3
        || bits_per_sample != 8
    {
        return Err("The selected image has an unsupported pixel format or size.".to_owned());
    }

    let row_bytes = width
        .checked_mul(channels)
        .ok_or_else(|| "The selected image dimensions are too large.".to_owned())?;
    if rowstride < row_bytes {
        return Err("The selected image contains invalid pixel data.".to_owned());
    }
    let required_bytes = rowstride
        .checked_mul(height.saturating_sub(1))
        .and_then(|length| length.checked_add(row_bytes))
        .ok_or_else(|| "The selected image dimensions are too large.".to_owned())?;

    let pixel_bytes = pixbuf.read_pixel_bytes();
    let pixels = pixel_bytes.as_ref();
    if pixels.len() < required_bytes {
        return Err("The selected image contains incomplete pixel data.".to_owned());
    }

    let pixel_count = width
        .checked_mul(height)
        .ok_or_else(|| "The selected image dimensions are too large.".to_owned())?;
    let mut grayscale = Zeroizing::new(Vec::with_capacity(pixel_count));
    for y in 0..height {
        let row_start = y * rowstride;
        for x in 0..width {
            let offset = row_start + x * channels;
            let red = u32::from(pixels[offset]);
            let green = u32::from(pixels[offset + 1]);
            let blue = u32::from(pixels[offset + 2]);
            let luminance = (red * 299 + green * 587 + blue * 114 + 500) / 1000;
            grayscale.push(luminance as u8);
        }
    }

    let mut decoder = quircs::Quirc::default();
    let mut selected_uri: Option<Zeroizing<String>> = None;
    for candidate in decoder.identify(width, height, grayscale.as_slice()) {
        let Ok(candidate) = candidate else {
            continue;
        };
        let Ok(decoded) = candidate.decode() else {
            continue;
        };
        let payload = Zeroizing::new(decoded.payload);
        let is_otpauth = payload
            .get(..10)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"otpauth://"));
        if !is_otpauth {
            continue;
        }
        if payload.len() > MAX_URI_BYTES {
            return Err("The QR code contains a provisioning URI larger than 4096 bytes.".to_owned());
        }
        let value = std::str::from_utf8(&payload)
            .map_err(|_| "The QR code does not contain a valid provisioning URI.")?;
        if selected_uri.is_some() {
            return Err("The image contains multiple authenticator QR codes. Choose an image with one code at a time.".to_owned());
        }
        selected_uri = Some(Zeroizing::new(value.to_owned()));
    }

    selected_uri.ok_or_else(|| {
        "No valid otpauth:// QR code was found in the selected image.".to_owned()
    })
}

fn persist_vault(vault: &mut AuthenticatedVault, directory: &Path) -> Result<(), String> {
    let plaintext = vault.accounts.encode().map_err(|error| error.to_string())?;
    vault
        .session
        .replace_plaintext(plaintext)
        .map_err(|error| error.to_string())?;

    let encrypted = vault
        .session
        .seal_current()
        .map_err(|error| error.to_string())?;
    let store = VaultStore::open(directory).map_err(|error| error.to_string())?;
    store.save(&encrypted).map_err(|error| error.to_string())
}

fn advance_hotp_and_persist(
    unlocked: &Rc<RefCell<Option<AuthenticatedVault>>>,
    directory: &Path,
    id: &[u8; 16],
) -> Result<(String, String, u64), String> {
    let mut guard = unlocked.borrow_mut();
    let vault = guard
        .as_mut()
        .ok_or_else(|| "The vault is locked.".to_owned())?;
    let account = vault
        .accounts
        .get_mut(id)
        .ok_or_else(|| "The account no longer exists.".to_owned())?;

    let used_code = account
        .generate_code(0)
        .map_err(|error| error.to_string())?;
    let next_counter = account
        .advance_hotp_counter()
        .map_err(|error| error.to_string())?;
    let next_code = account
        .generate_code(0)
        .map_err(|error| error.to_string())?;

    persist_vault(vault, directory)?;
    Ok((used_code, next_code, next_counter))
}

struct AccountRowWidgets {
    id: [u8; 16],
    code: Label,
    countdown: Label,
}

fn algorithm_name(algorithm: OtpAlgorithm) -> &'static str {
    match algorithm {
        OtpAlgorithm::Sha1 => "SHA1",
        OtpAlgorithm::Sha256 => "SHA256",
        OtpAlgorithm::Sha512 => "SHA512",
    }
}

fn show_edit_account_page(
    stack: &Stack,
    window: &ApplicationWindow,
    directory: PathBuf,
    unlocked: Rc<RefCell<Option<AuthenticatedVault>>>,
    id: [u8; 16],
) {
    let snapshot = {
        let borrowed = unlocked.borrow();
        borrowed.as_ref().and_then(|vault| {
            vault
                .accounts
                .accounts()
                .iter()
                .find(|account| account.id() == &id)
                .map(|account| {
                    let (mode, parameter) = match account.mode() {
                        AccountMode::Totp { period_seconds } => ("TOTP", period_seconds),
                        AccountMode::Hotp { counter } => ("HOTP", counter),
                    };
                    (
                        account.issuer().to_owned(),
                        account.label().to_owned(),
                        algorithm_name(account.algorithm()),
                        account.digits(),
                        mode,
                        parameter,
                    )
                })
        })
    };
    let Some((
        issuer_value,
        label_value,
        algorithm_value,
        digits_value,
        mode_value,
        parameter_value,
    )) = snapshot
    else {
        show_message_dialog(
            window,
            "Account unavailable",
            "This account no longer exists in the unlocked vault.",
        );
        return;
    };

    let page = GtkBox::new(Orientation::Vertical, 14);
    page.set_margin_top(28);
    page.set_margin_bottom(28);
    page.set_margin_start(28);
    page.set_margin_end(28);

    let title = Label::new(Some("Edit account"));
    title.add_css_class("title-1");
    title.set_xalign(0.0);

    let description = Label::new(Some(
        "Leave the replacement-secret field blank to keep the current secret. The existing secret is never displayed.",
    ));
    description.set_wrap(true);
    description.set_xalign(0.0);
    description.add_css_class("dim-label");

    let issuer = labeled_entry(&page, "Issuer (optional)", "Example: GitHub");
    issuer.set_max_length(256);
    issuer.set_text(&issuer_value);

    let label = labeled_entry(&page, "Account name", "Example: name@example.com");
    label.set_max_length(256);
    label.set_text(&label_value);

    let secret = labeled_entry(
        &page,
        "Replacement secret (Base32, optional)",
        "Leave blank to keep the current secret",
    );
    secret.set_visibility(false);
    secret.set_input_purpose(gtk::InputPurpose::Password);
    secret.set_widget_name("suika-secret-entry");
    secret.set_max_length(208);

    let mode_selection = if mode_value == "TOTP" { 0 } else { 1 };
    let (mode, _mode_field) =
        labeled_dropdown(&page, "OTP mode", &["TOTP", "HOTP"], mode_selection);
    let algorithm_selection = match algorithm_value {
        "SHA1" => 0,
        "SHA256" => 1,
        "SHA512" => 2,
        _ => 0,
    };
    let (algorithm, _algorithm_field) = labeled_dropdown(
        &page,
        "HMAC algorithm",
        &["SHA1", "SHA256", "SHA512"],
        algorithm_selection,
    );
    let digit_selection = digits_value.saturating_sub(6).min(2) as u32;
    let (digits, _digits_field) =
        labeled_dropdown(&page, "Code digits", &["6", "7", "8"], digit_selection);
    let period_selection = TOTP_PERIOD_PRESETS
        .iter()
        .position(|value| *value == parameter_value)
        .map_or(TOTP_PERIOD_PRESETS.len() as u32, |index| index as u32);
    let (period, period_field) = labeled_dropdown(
        &page,
        "TOTP period",
        &[
            "15 seconds",
            "30 seconds",
            "45 seconds",
            "60 seconds",
            "90 seconds",
            "120 seconds",
            "300 seconds",
            "Custom…",
        ],
        period_selection,
    );
    let counter_selection = HOTP_COUNTER_PRESETS
        .iter()
        .position(|value| *value == parameter_value)
        .map_or(HOTP_COUNTER_PRESETS.len() as u32, |index| index as u32);
    let (counter, counter_field) = labeled_dropdown(
        &page,
        "HOTP initial counter",
        &["0", "1", "2", "5", "10", "100", "Custom…"],
        counter_selection,
    );
    let (custom_parameter_field, custom_parameter) = labeled_entry_field(
        &page,
        "Custom period (seconds) or counter",
        "Enter a positive period or counter value",
    );
    if (mode_selection == 0 && period_selection == TOTP_PERIOD_PRESETS.len() as u32)
        || (mode_selection == 1 && counter_selection == HOTP_COUNTER_PRESETS.len() as u32)
    {
        custom_parameter.set_text(&parameter_value.to_string());
    }
    bind_parameter_fields(
        &mode,
        &period,
        &period_field,
        &counter,
        &counter_field,
        &custom_parameter_field,
    );

    let status = Label::new(None);
    status.set_wrap(true);
    status.set_xalign(0.0);

    let buttons = GtkBox::new(Orientation::Horizontal, 8);
    let back = Button::with_label("Cancel");
    let save = Button::with_label("Save changes");
    save.add_css_class("suggested-action");
    save.set_hexpand(true);
    buttons.append(&back);
    buttons.append(&save);

    page.append(&title);
    page.append(&description);
    page.append(&status);
    page.append(&buttons);

    let stack_weak = stack.downgrade();
    let window_weak = window.downgrade();
    let directory_for_back = directory.clone();
    let unlocked_for_back = unlocked.clone();
    let secret_for_back = secret.clone();
    back.connect_clicked(move |_| {
        secret_for_back.set_text("");
        if let (Some(stack), Some(window)) = (stack_weak.upgrade(), window_weak.upgrade()) {
            show_accounts_page(
                &stack,
                &window,
                directory_for_back.clone(),
                unlocked_for_back.clone(),
            );
        }
    });

    let stack_weak = stack.downgrade();
    let window_weak = window.downgrade();
    let directory_for_save = directory.clone();
    let unlocked_for_save = unlocked.clone();
    let issuer_for_save = issuer.clone();
    let label_for_save = label.clone();
    let secret_for_save = secret.clone();
    let mode_for_save = mode.clone();
    let algorithm_for_save = algorithm.clone();
    let digits_for_save = digits.clone();
    let period_for_save = period.clone();
    let counter_for_save = counter.clone();
    let custom_parameter_for_save = custom_parameter.clone();
    let status_for_save = status.clone();
    let save_for_save = save.clone();

    save.connect_clicked(move |_| {
        let issuer_value = issuer_for_save.text().trim().to_owned();
        let label_value = label_for_save.text().trim().to_owned();
        let secret_text = Zeroizing::new(secret_for_save.text().to_string());
        secret_for_save.set_text("");

        let mode = match mode_for_save.selected() {
            0 => "TOTP",
            1 => "HOTP",
            _ => {
                status_for_save.set_text("Choose TOTP or HOTP as the OTP mode.");
                return;
            }
        };

        let algorithm = match algorithm_for_save.selected() {
            0 => OtpAlgorithm::Sha1,
            1 => OtpAlgorithm::Sha256,
            2 => OtpAlgorithm::Sha512,
            _ => {
                status_for_save.set_text("Choose SHA1, SHA256, or SHA512.");
                return;
            }
        };
        let digits = match digits_for_save.selected() {
            value @ 0..=2 => (value + 6) as u8,
            _ => {
                status_for_save.set_text("Choose a code length of 6, 7, or 8 digits.");
                return;
            }
        };
        let parameter = match selected_parameter(
            mode_for_save.selected(),
            period_for_save.selected(),
            counter_for_save.selected(),
            custom_parameter_for_save.text().as_str(),
        ) {
            Ok(value) => value,
            Err(message) => {
                status_for_save.set_text(message);
                return;
            }
        };
        let otp_mode = if mode == "TOTP" {
            if !(1..=86_400).contains(&parameter) {
                status_for_save.set_text("TOTP period must be between 1 and 86400 seconds.");
                return;
            }
            AccountMode::Totp {
                period_seconds: parameter,
            }
        } else {
            AccountMode::Hotp { counter: parameter }
        };
        if label_value.trim().is_empty() {
            status_for_save.set_text("Enter an account name.");
            return;
        }

        let replacement_secret = if secret_text.is_empty() {
            None
        } else {
            match decode_base32(secret_text.as_str()) {
                Ok(value) if value.len() >= 16 => Some(value),
                Ok(_) => {
                    status_for_save.set_text("Use a secret containing at least 16 decoded bytes.");
                    return;
                }
                Err(message) => {
                    status_for_save.set_text(&message.to_string());
                    return;
                }
            }
        };

        save_for_save.set_sensitive(false);
        status_for_save.set_text("Encrypting and saving changes…");

        let result = {
            let mut guard = unlocked_for_save.borrow_mut();
            match guard.as_mut() {
                Some(vault) => {
                    let update_result = vault
                        .accounts
                        .get_mut(&id)
                        .ok_or_else(|| "The account no longer exists.".to_owned())
                        .and_then(|account| {
                            account
                                .update(
                                    issuer_value,
                                    label_value,
                                    replacement_secret,
                                    algorithm,
                                    digits,
                                    otp_mode,
                                )
                                .map_err(|error| error.to_string())
                        });
                    match update_result {
                        Ok(()) => persist_vault(vault, &directory_for_save),
                        Err(message) => Err(message),
                    }
                }
                None => Err("The vault is locked.".to_owned()),
            }
        };

        save_for_save.set_sensitive(true);
        match result {
            Ok(()) => {
                if let (Some(stack), Some(window)) =
                    (stack_weak.upgrade(), window_weak.upgrade())
                {
                    show_accounts_page(
                        &stack,
                        &window,
                        directory_for_save.clone(),
                        unlocked_for_save.clone(),
                    );
                }
            }
            Err(message) => {
                status_for_save.set_text(&format!(
                    "Changes remain in this unlocked session, but the disk save was not confirmed: {message}"
                ));
            }
        }
    });

    replace_page(stack, "edit-account", &page);
}

fn show_message_dialog(window: &ApplicationWindow, title: &str, message: &str) {
    let alert = gtk::AlertDialog::builder()
        .message(title)
        .detail(message)
        .buttons(["Close"])
        .modal(true)
        .build();
    alert.show(Some(window));
}

fn confirm_remove_account(
    window: &ApplicationWindow,
    stack: &Stack,
    directory: PathBuf,
    unlocked: Rc<RefCell<Option<AuthenticatedVault>>>,
    id: [u8; 16],
) {
    let alert = gtk::AlertDialog::builder()
        .message("Remove this account?")
        .detail("The account and its secret will be removed from the encrypted vault.")
        .buttons(["Cancel", "Remove"])
        .cancel_button(0)
        .default_button(0)
        .modal(true)
        .build();

    let stack_weak = stack.downgrade();
    let window_weak = window.downgrade();
    let directory_for_remove = directory.clone();
    let unlocked_for_remove = unlocked.clone();
    alert.choose(
        Some(window),
        None::<&gtk::gio::Cancellable>,
        move |response| {
            if !matches!(response, Ok(1)) {
                return;
            }

            let result = {
                let mut guard = unlocked_for_remove.borrow_mut();
                match guard.as_mut() {
                    Some(vault) => {
                        if vault.accounts.remove(&id) {
                            persist_vault(vault, &directory_for_remove)
                        } else {
                            Err("The account no longer exists.".to_owned())
                        }
                    }
                    None => Err("The vault is locked.".to_owned()),
                }
            };

            if let (Some(stack), Some(window)) = (stack_weak.upgrade(), window_weak.upgrade()) {
                show_accounts_page(
                    &stack,
                    &window,
                    directory_for_remove.clone(),
                    unlocked_for_remove.clone(),
                );
                if let Err(message) = result {
                    show_message_dialog(&window, "Account removal was not saved", &message);
                }
            }
        },
    );
}

fn show_accounts_page(
    stack: &Stack,
    window: &ApplicationWindow,
    directory: PathBuf,
    unlocked: Rc<RefCell<Option<AuthenticatedVault>>>,
) {
    for name in ["add-account", "edit-account"] {
        if let Some(form_page) = stack.child_by_name(name) {
            stack.remove(&form_page);
        }
    }

    let page = GtkBox::new(Orientation::Vertical, 14);
    page.set_margin_top(24);
    page.set_margin_bottom(24);
    page.set_margin_start(24);
    page.set_margin_end(24);

    let header = GtkBox::new(Orientation::Horizontal, 8);
    let title = Label::new(Some("Your accounts"));
    title.add_css_class("title-1");
    title.set_hexpand(true);
    title.set_xalign(0.0);
    let add = Button::with_label("Add account");
    let lock = Button::with_label("Lock");
    header.append(&title);
    header.append(&add);
    header.append(&lock);
    page.append(&header);

    let stack_for_add = stack.downgrade();
    let window_for_add = window.downgrade();
    let directory_for_add = directory.clone();
    let unlocked_for_add = unlocked.clone();
    add.connect_clicked(move |_| {
        if let (Some(stack), Some(window)) = (stack_for_add.upgrade(), window_for_add.upgrade()) {
            show_add_account_page(
                &stack,
                &window,
                directory_for_add.clone(),
                unlocked_for_add.clone(),
            );
        }
    });

    let count = unlocked
        .borrow()
        .as_ref()
        .map_or(0, |vault| vault.accounts.len());
    let summary = Label::new(Some(&format!(
        "{count} {} in your encrypted vault",
        if count == 1 { "account" } else { "accounts" }
    )));
    summary.add_css_class("dim-label");
    summary.set_xalign(0.0);
    page.append(&summary);

    let search = Entry::new();
    search.set_placeholder_text(Some("Search issuer or account…"));
    search.set_hexpand(true);
    page.append(&search);

    let list = ListBox::new();
    list.set_selection_mode(gtk::SelectionMode::None);
    list.add_css_class("boxed-list");

    let mut row_widgets = Vec::new();
    let mut searchable_rows: Vec<(ListBoxRow, String)> = Vec::new();
    if let Some(vault) = unlocked.borrow().as_ref() {
        if vault.accounts.is_empty() {
            let empty = GtkBox::new(Orientation::Vertical, 8);
            empty.set_margin_top(32);
            empty.set_margin_bottom(32);
            let empty_title = Label::new(Some("No accounts yet"));
            empty_title.add_css_class("title-2");
            let empty_hint = Label::new(Some(
                "Your encrypted vault is ready. Use Add account to enroll a TOTP or HOTP token.",
            ));
            empty_hint.set_wrap(true);
            empty_hint.set_justify(gtk::Justification::Center);
            empty_hint.add_css_class("dim-label");
            empty.append(&empty_title);
            empty.append(&empty_hint);

            let row = ListBoxRow::new();
            row.set_child(Some(&empty));
            row.set_activatable(false);
            row.set_selectable(false);
            list.append(&row);
        } else {
            for account in vault.accounts.accounts() {
                let row_content = GtkBox::new(Orientation::Horizontal, 12);
                row_content.set_margin_top(12);
                row_content.set_margin_bottom(12);
                row_content.set_margin_start(12);
                row_content.set_margin_end(12);

                let identity = GtkBox::new(Orientation::Vertical, 4);
                identity.set_hexpand(true);
                let issuer = if account.issuer().is_empty() {
                    account.label()
                } else {
                    account.issuer()
                };

                let issuer_label = Label::new(Some(issuer));
                issuer_label.set_xalign(0.0);
                issuer_label.add_css_class("heading");

                let account_label = Label::new(Some(account.label()));
                account_label.set_xalign(0.0);
                account_label.add_css_class("dim-label");

                let code = Label::new(Some(
                    &account
                        .generate_code(unix_time())
                        .unwrap_or_else(|_| "------".to_owned()),
                ));
                code.set_xalign(0.0);
                code.set_selectable(true);
                code.add_css_class("monospace");
                code.add_css_class("title-2");

                let countdown = Label::new(None);
                countdown.set_xalign(0.0);
                countdown.add_css_class("dim-label");

                identity.append(&issuer_label);
                identity.append(&account_label);
                identity.append(&code);
                identity.append(&countdown);

                row_content.append(&identity);

                match account.mode() {
                    AccountMode::Totp { .. } => {
                        let copy = Button::with_label("Copy");
                        let code_for_copy = code.clone();
                        copy.connect_clicked(move |_| {
                            if let Some(display) = gtk::gdk::Display::default() {
                                let value = code_for_copy.text().to_string();
                                if value != "------" {
                                    display.clipboard().set_text(&value);
                                }
                            }
                        });
                        row_content.append(&copy);
                    }
                    AccountMode::Hotp { .. } => {
                        let advance = Button::with_label("Copy & next");
                        let id = *account.id();
                        let unlocked_for_advance = unlocked.clone();
                        let directory_for_advance = directory.clone();
                        let code_for_advance = code.clone();
                        let countdown_for_advance = countdown.clone();
                        advance.connect_clicked(move |_| {
                            match advance_hotp_and_persist(
                                &unlocked_for_advance,
                                &directory_for_advance,
                                &id,
                            ) {
                                Ok((used_code, next_code, next_counter)) => {
                                    code_for_advance.set_text(&next_code);
                                    countdown_for_advance
                                        .set_text(&format!("Counter {next_counter}"));
                                    if let Some(display) = gtk::gdk::Display::default() {
                                        display.clipboard().set_text(&used_code);
                                    }
                                }
                                Err(message) => {
                                    countdown_for_advance
                                        .set_text(&format!("Counter not advanced: {message}"));
                                }
                            }
                        });
                        row_content.append(&advance);
                    }
                }

                let edit = Button::with_label("Edit");
                let edit_id = *account.id();
                let stack_for_edit = stack.downgrade();
                let window_for_edit = window.downgrade();
                let directory_for_edit = directory.clone();
                let unlocked_for_edit = unlocked.clone();
                edit.connect_clicked(move |_| {
                    if let (Some(stack), Some(window)) =
                        (stack_for_edit.upgrade(), window_for_edit.upgrade())
                    {
                        show_edit_account_page(
                            &stack,
                            &window,
                            directory_for_edit.clone(),
                            unlocked_for_edit.clone(),
                            edit_id,
                        );
                    }
                });
                row_content.append(&edit);

                let remove = Button::with_label("Remove");
                let remove_id = *account.id();
                let stack_for_remove = stack.downgrade();
                let window_for_remove = window.downgrade();
                let directory_for_remove = directory.clone();
                let unlocked_for_remove = unlocked.clone();
                remove.connect_clicked(move |_| {
                    if let (Some(stack), Some(window)) =
                        (stack_for_remove.upgrade(), window_for_remove.upgrade())
                    {
                        confirm_remove_account(
                            &window,
                            &stack,
                            directory_for_remove.clone(),
                            unlocked_for_remove.clone(),
                            remove_id,
                        );
                    }
                });
                row_content.append(&remove);

                let row = ListBoxRow::new();
                row.set_child(Some(&row_content));
                row.set_activatable(false);
                row.set_selectable(false);
                list.append(&row);
                searchable_rows.push((
                    row.clone(),
                    format!("{} {}", account.issuer(), account.label()).to_lowercase(),
                ));

                row_widgets.push(AccountRowWidgets {
                    id: *account.id(),
                    code,
                    countdown,
                });
            }
        }
    }

    let search_rows = searchable_rows;
    search.connect_changed(move |entry| {
        let query = entry.text().trim().to_lowercase();
        for (row, searchable_text) in &search_rows {
            row.set_visible(query.is_empty() || searchable_text.contains(&query));
        }
    });

    let scrolled = ScrolledWindow::new();
    scrolled.set_policy(gtk::PolicyType::Never, gtk::PolicyType::Automatic);
    scrolled.set_vexpand(true);
    scrolled.set_child(Some(&list));
    page.append(&scrolled);

    let footer = Label::new(Some("Offline vault • Stored in ~/.SuikaAuthenticator/"));
    footer.set_xalign(0.0);
    footer.add_css_class("dim-label");
    page.append(&footer);

    let stack_for_lock = stack.downgrade();
    let window_for_lock = window.downgrade();
    let directory_for_lock = directory.clone();
    let unlocked_for_lock = unlocked.clone();
    lock.connect_clicked(move |_| {
        if let (Some(stack), Some(window)) = (stack_for_lock.upgrade(), window_for_lock.upgrade()) {
            lock_vault_to_auth(
                &stack,
                &window,
                directory_for_lock.clone(),
                unlocked_for_lock.clone(),
            );
        }
    });

    if !row_widgets.is_empty() {
        let unlocked_for_timer = unlocked.clone();
        let page_for_timer = page.clone();
        glib::source::timeout_add_seconds_local(1, move || {
            if !page_for_timer.is_mapped() {
                return ControlFlow::Break;
            }

            let borrowed = unlocked_for_timer.borrow();
            let Some(vault) = borrowed.as_ref() else {
                return ControlFlow::Break;
            };

            let now = unix_time();
            for row in &row_widgets {
                if let Some(account) = vault
                    .accounts
                    .accounts()
                    .iter()
                    .find(|account| account.id() == &row.id)
                {
                    let code = account
                        .generate_code(now)
                        .unwrap_or_else(|_| "------".to_owned());
                    row.code.set_text(&code);

                    match account.mode() {
                        AccountMode::Totp { period_seconds } => {
                            let remaining = period_seconds - (now % period_seconds);
                            row.countdown
                                .set_text(&format!("Refreshes in {remaining}s"));
                        }
                        AccountMode::Hotp { counter } => {
                            row.countdown.set_text(&format!("Counter {counter}"));
                        }
                    }
                }
            }

            ControlFlow::Continue
        });
    }

    replace_page(stack, "accounts", &page);
}

fn unix_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parameter_dropdowns_map_presets_and_custom_values() {
        assert_eq!(selected_parameter(0, 1, 0, ""), Ok(30));
        assert_eq!(selected_parameter(0, 7, 0, "42"), Ok(42));
        assert_eq!(selected_parameter(1, 1, 3, ""), Ok(5));
        assert_eq!(selected_parameter(1, 1, 6, "1234"), Ok(1234));
        assert!(selected_parameter(0, 7, 0, "not a number").is_err());
        assert!(selected_parameter(1, 1, 99, "").is_err());
    }

    #[test]
    fn base32_decodes_rfc4648_vectors() {
        assert_eq!(
            decode_base32("MY======").expect("valid Base32").as_slice(),
            b"f"
        );
        assert_eq!(
            decode_base32("MZXQ====").expect("valid Base32").as_slice(),
            b"fo"
        );
        assert_eq!(
            decode_base32("MZXW6===").expect("valid Base32").as_slice(),
            b"foo"
        );
        assert_eq!(
            decode_base32("MZXW6YQ=").expect("valid Base32").as_slice(),
            b"foob"
        );
        assert_eq!(
            decode_base32("MZXW6YTB").expect("valid Base32").as_slice(),
            b"fooba"
        );
        assert_eq!(
            decode_base32("MZXW6YTBOI======")
                .expect("valid Base32")
                .as_slice(),
            b"foobar"
        );
    }

    #[test]
    fn base32_accepts_lowercase_spaces_and_hyphens() {
        assert_eq!(
            decode_base32("mzxw6 ytb-oi======")
                .expect("valid Base32")
                .as_slice(),
            b"foobar"
        );
    }

    #[test]
    fn base32_rejects_bad_characters_padding_and_trailing_bits() {
        assert!(decode_base32("MZXW6YTB!").is_err());
        assert!(decode_base32("MZXW6YTBOI=====").is_err());
        assert!(decode_base32("MZ======").is_err());
        assert!(decode_base32("MZX").is_err());
    }
}
