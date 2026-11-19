//! Native GTK4 frontend for SuikaAuthenticator.
//!
//! The shared core owns vault and account cryptography. This binary owns only
//! GTK presentation and the Linux application-directory choice.

use std::cell::{Cell, RefCell};
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
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
use suika_core::aegis::{AegisImportResult, import_aegis_export};
use suika_core::backup::{Backup, MAX_BACKUP_FILE_BYTES};
use suika_core::base32::decode_base32;
use suika_core::crypto::KdfParams;
use suika_core::otp::OtpAlgorithm;
use suika_core::otpauth::{
    MAX_OTPAUTH_URI_LIST_BYTES, OtpAuthError, parse_otpauth_uri, parse_otpauth_uri_list,
};
use suika_core::storage::{StorageError, VaultStore};
use suika_core::vault::{Vault, VaultError, VaultSession};
use zeroize::Zeroizing;

const APP_ID: &str = "org.suika.SuikaAuthenticator";
const DATA_DIRECTORY: &str = ".SuikaAuthenticator";
const INACTIVITY_LOCK_TIMEOUT: Duration = Duration::from_secs(5 * 60);

thread_local! {
    static LAST_ACTIVITY: Cell<Instant> = Cell::new(Instant::now());
    static OTP_CLIPBOARD_GENERATION: Cell<u64> = const { Cell::new(0) };
}

fn record_activity() {
    LAST_ACTIVITY.with(|last| last.set(Instant::now()));
}

fn inactivity_duration() -> Duration {
    LAST_ACTIVITY.with(|last| Instant::now().saturating_duration_since(last.get()))
}

/// Copy an OTP and clear it after 30 seconds only if it is still the
/// application-owned clipboard value. External clipboard contents are untouched.
fn copy_otp_to_clipboard(clipboard: &gtk::gdk::Clipboard, code: String) {
    let expected = Rc::new(Zeroizing::new(code));
    clipboard.set_text(expected.as_str());
    let generation = OTP_CLIPBOARD_GENERATION.with(|current| {
        let next = current.get().wrapping_add(1);
        current.set(next);
        next
    });
    let clipboard = clipboard.clone();

    glib::source::timeout_add_local(Duration::from_secs(30), move || {
        let is_current = OTP_CLIPBOARD_GENERATION.with(|current| current.get() == generation);
        if is_current && clipboard.is_local() {
            let clipboard_for_read = clipboard.clone();
            let expected_for_read = expected.clone();
            clipboard.read_text_async(None::<&gio::Cancellable>, move |result| {
                let is_current =
                    OTP_CLIPBOARD_GENERATION.with(|current| current.get() == generation);
                let matches_otp =
                    result.is_ok_and(|text| text.as_deref() == Some(expected_for_read.as_str()));

                if is_current && clipboard_for_read.is_local() && matches_otp {
                    let _ = clipboard_for_read.set_content(None::<&gtk::gdk::ContentProvider>);
                }
            });
        }
        ControlFlow::Break
    });
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
        .default_width(940)
        .default_height(660)
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
            return Err(
                "The QR code contains a provisioning URI larger than 4096 bytes.".to_owned(),
            );
        }
        let value = std::str::from_utf8(&payload)
            .map_err(|_| "The QR code does not contain a valid provisioning URI.")?;
        if selected_uri.is_some() {
            return Err("The image contains multiple authenticator QR codes. Choose an image with one code at a time.".to_owned());
        }
        selected_uri = Some(Zeroizing::new(value.to_owned()));
    }

    selected_uri
        .ok_or_else(|| "No valid otpauth:// QR code was found in the selected image.".to_owned())
}

fn show_aegis_import_page(
    stack: &Stack,
    window: &ApplicationWindow,
    directory: PathBuf,
    unlocked: Rc<RefCell<Option<AuthenticatedVault>>>,
    path: PathBuf,
) {
    let page = GtkBox::new(Orientation::Vertical, 14);
    page.set_margin_top(28);
    page.set_margin_bottom(28);
    page.set_margin_start(28);
    page.set_margin_end(28);

    let title = Label::new(Some("Import Aegis export"));
    title.add_css_class("title-1");
    title.set_xalign(0.0);
    let description = Label::new(Some(
        "Import a plaintext or password-encrypted Aegis JSON export. Leave the password blank for plaintext exports. Only standard TOTP/HOTP entries are imported; unsupported Aegis token types are skipped.",
    ));
    description.set_wrap(true);
    description.set_xalign(0.0);
    description.add_css_class("dim-label");

    let filename = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("Aegis export");
    let file_label = Label::new(Some(&format!("Selected file: {filename}")));
    file_label.set_xalign(0.0);
    file_label.set_ellipsize(gtk::pango::EllipsizeMode::Middle);

    let password = labeled_entry(
        &page,
        "Aegis export password (optional)",
        "Leave blank for an unencrypted export",
    );
    password.set_visibility(false);
    password.set_input_purpose(gtk::InputPurpose::Password);
    password.set_widget_name("suika-secret-entry");
    password.set_max_length(4096);

    let status = Label::new(None);
    status.set_wrap(true);
    status.set_xalign(0.0);
    let buttons = GtkBox::new(Orientation::Horizontal, 8);
    let cancel = Button::with_label("Cancel");
    let import = Button::with_label("Import accounts");
    import.add_css_class("suggested-action");
    import.set_hexpand(true);
    buttons.append(&cancel);
    buttons.append(&import);

    page.append(&title);
    page.append(&description);
    page.append(&file_label);
    page.append(&status);
    page.append(&buttons);

    let stack_weak = stack.downgrade();
    let window_weak = window.downgrade();
    let directory_for_cancel = directory.clone();
    let unlocked_for_cancel = unlocked.clone();
    let password_for_cancel = password.clone();
    cancel.connect_clicked(move |_| {
        password_for_cancel.set_text("");
        if let (Some(stack), Some(window)) = (stack_weak.upgrade(), window_weak.upgrade()) {
            show_accounts_page(
                &stack,
                &window,
                directory_for_cancel.clone(),
                unlocked_for_cancel.clone(),
            );
        }
    });

    let status_for_import = status.clone();
    let import_for_import = import.clone();
    let password_for_import = password.clone();
    let directory_for_import = directory.clone();
    let unlocked_for_import = unlocked.clone();
    let stack_weak = stack.downgrade();
    let window_weak = window.downgrade();
    import.connect_clicked(move |_| {
        let password_value = Zeroizing::new(password_for_import.text().as_bytes().to_vec());
        password_for_import.set_text("");
        import_for_import.set_sensitive(false);
        status_for_import.set_text("Reading, validating, and importing the export…");

        let path = path.clone();
        let (sender, receiver) = mpsc::sync_channel(1);
        let worker = thread::Builder::new()
            .name("suika-aegis-import".to_owned())
            .spawn(move || {
                let result = load_aegis_export(&path, password_value.as_slice());
                let _ = sender.send(result);
            });
        if let Err(error) = worker {
            import_for_import.set_sensitive(true);
            status_for_import.set_text(&format!("Could not start the import worker: {error}"));
            return;
        }

        let status_for_completion = status_for_import.clone();
        let import_for_completion = import_for_import.clone();
        let directory_for_completion = directory_for_import.clone();
        let unlocked_for_completion = unlocked_for_import.clone();
        let stack_for_completion = stack_weak.clone();
        let window_for_completion = window_weak.clone();
        let mut completed = Some(move |result: Result<AegisImportResult, String>| {
            import_for_completion.set_sensitive(true);
            match result {
                Ok(imported_accounts) => {
                    match persist_aegis_import(
                        &unlocked_for_completion,
                        &directory_for_completion,
                        imported_accounts,
                    ) {
                        Ok((imported, skipped)) => {
                            if let (Some(stack), Some(window)) = (
                                stack_for_completion.upgrade(),
                                window_for_completion.upgrade(),
                            ) {
                                show_accounts_page(
                                    &stack,
                                    &window,
                                    directory_for_completion.clone(),
                                    unlocked_for_completion.clone(),
                                );
                                show_message_dialog(
                                    &window,
                                    "Aegis import complete",
                                    &format!(
                                        "Imported {imported} standard TOTP/HOTP account(s). Skipped {skipped} unsupported entry/entries. The imported accounts are now stored in your encrypted vault."
                                    ),
                                );
                            }
                        }
                        Err(message) => status_for_completion.set_text(&message),
                    }
                }
                Err(message) => status_for_completion.set_text(&message),
            }
        });
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
                        callback(Err("The Aegis import worker stopped unexpectedly.".to_owned()));
                    }
                    ControlFlow::Break
                }
            }
        });
    });

    replace_page(stack, "aegis-import", &page);
}

fn load_aegis_export(path: &Path, password: &[u8]) -> Result<AegisImportResult, String> {
    const MAX_EXPORT_BYTES: u64 = 16 * 1024 * 1024;
    let metadata =
        fs::metadata(path).map_err(|_| "The selected Aegis export could not be opened.")?;
    if !metadata.is_file() || metadata.len() > MAX_EXPORT_BYTES {
        return Err("Choose a regular Aegis JSON export no larger than 16 MiB.".to_owned());
    }
    let file = fs::File::open(path).map_err(|_| "The selected Aegis export could not be read.")?;
    let mut input = Zeroizing::new(Vec::with_capacity(metadata.len() as usize));
    let bytes_read = file
        .take(metadata.len())
        .read_to_end(&mut input)
        .map_err(|_| "The selected Aegis export could not be read.")?;
    if bytes_read as u64 != metadata.len() {
        return Err("The selected Aegis export changed while it was being read.".to_owned());
    }

    import_aegis_export(
        &input,
        if password.is_empty() {
            None
        } else {
            Some(password)
        },
    )
    .map_err(|error| error.to_string())
}

fn persist_aegis_import(
    unlocked: &Rc<RefCell<Option<AuthenticatedVault>>>,
    directory: &Path,
    imported: AegisImportResult,
) -> Result<(usize, usize), String> {
    let imported_count = imported.accounts.len();
    let skipped = imported.skipped_unsupported;
    if imported_count == 0 {
        return Err(if skipped == 0 {
            "The Aegis export contains no accounts.".to_owned()
        } else {
            format!(
                "No supported TOTP/HOTP accounts were found; {skipped} unsupported entries were skipped."
            )
        });
    }

    let mut guard = unlocked.borrow_mut();
    let vault = guard
        .as_mut()
        .ok_or_else(|| "The vault is locked. Unlock it before importing accounts.".to_owned())?;

    let existing = vault.accounts.encode().map_err(|error| error.to_string())?;
    let mut candidate = AccountDatabase::decode(&existing).map_err(|error| error.to_string())?;
    for account in imported.accounts {
        candidate
            .insert(account)
            .map_err(|error| error.to_string())?;
    }

    let store = VaultStore::open(directory).map_err(|error| error.to_string())?;
    let candidate_plaintext = candidate.encode().map_err(|error| error.to_string())?;
    let previous_plaintext = Zeroizing::new(vault.session.plaintext().to_vec());
    vault
        .session
        .replace_plaintext(candidate_plaintext)
        .map_err(|error| error.to_string())?;

    let encrypted = match vault.session.seal_current() {
        Ok(encrypted) => encrypted,
        Err(error) => {
            let _ = vault.session.replace_plaintext(previous_plaintext);
            return Err(error.to_string());
        }
    };
    if let Err(error) = store.save(&encrypted) {
        let _ = vault.session.replace_plaintext(previous_plaintext);
        return Err(error.to_string());
    }

    vault.accounts = candidate;
    Ok((imported_count, skipped))
}

fn show_otpauth_uri_list_import_page(
    stack: &Stack,
    window: &ApplicationWindow,
    directory: PathBuf,
    unlocked: Rc<RefCell<Option<AuthenticatedVault>>>,
    path: PathBuf,
) {
    let page = GtkBox::new(Orientation::Vertical, 14);
    page.set_margin_top(28);
    page.set_margin_bottom(28);
    page.set_margin_start(28);
    page.set_margin_end(28);

    let title = Label::new(Some("Import plaintext URI list"));
    title.add_css_class("title-1");
    title.set_xalign(0.0);
    let description = Label::new(Some(
        "Import a plaintext text export containing one otpauth:// URI per line, including Ente Auth plaintext exports. All non-empty lines must be valid TOTP/HOTP provisioning URIs. The source file is not modified and contains unencrypted secret keys; import only trusted files and delete the source when no longer needed.",
    ));
    description.set_wrap(true);
    description.set_xalign(0.0);
    description.add_css_class("dim-label");

    let filename = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("text export");
    let file_label = Label::new(Some(&format!("Selected file: {filename}")));
    file_label.set_xalign(0.0);
    file_label.set_ellipsize(gtk::pango::EllipsizeMode::Middle);

    let status = Label::new(Some(
        "The selected file is read locally and held in memory only.",
    ));
    status.set_wrap(true);
    status.set_xalign(0.0);
    let buttons = GtkBox::new(Orientation::Horizontal, 8);
    let cancel = Button::with_label("Cancel");
    let import = Button::with_label("Import accounts");
    import.add_css_class("suggested-action");
    import.set_hexpand(true);
    buttons.append(&cancel);
    buttons.append(&import);

    page.append(&title);
    page.append(&description);
    page.append(&file_label);
    page.append(&status);
    page.append(&buttons);

    let stack_weak = stack.downgrade();
    let window_weak = window.downgrade();
    let directory_for_cancel = directory.clone();
    let unlocked_for_cancel = unlocked.clone();
    cancel.connect_clicked(move |_| {
        if let (Some(stack), Some(window)) = (stack_weak.upgrade(), window_weak.upgrade()) {
            show_accounts_page(
                &stack,
                &window,
                directory_for_cancel.clone(),
                unlocked_for_cancel.clone(),
            );
        }
    });

    let status_for_import = status.clone();
    let import_for_import = import.clone();
    let directory_for_import = directory.clone();
    let unlocked_for_import = unlocked.clone();
    let stack_weak = stack.downgrade();
    let window_weak = window.downgrade();
    import.connect_clicked(move |_| {
        import_for_import.set_sensitive(false);
        cancel.set_sensitive(false);
        status_for_import.set_text("Reading and validating every provisioning URI…");

        let path = path.clone();
        let (sender, receiver) = mpsc::sync_channel(1);
        let worker = thread::Builder::new()
            .name("suika-uri-list-import".to_owned())
            .spawn(move || {
                let result = load_otpauth_uri_list(&path);
                let _ = sender.send(result);
            });
        if let Err(error) = worker {
            import_for_import.set_sensitive(true);
            cancel.set_sensitive(true);
            status_for_import.set_text(&format!("Could not start the import worker: {error}"));
            return;
        }

        let status_for_completion = status_for_import.clone();
        let import_for_completion = import_for_import.clone();
        let cancel_for_completion = cancel.clone();
        let directory_for_completion = directory_for_import.clone();
        let unlocked_for_completion = unlocked_for_import.clone();
        let stack_for_completion = stack_weak.clone();
        let window_for_completion = window_weak.clone();
        glib::source::timeout_add_local(Duration::from_millis(100), move || {
            match receiver.try_recv() {
                Ok(result) => {
                    import_for_completion.set_sensitive(true);
                    cancel_for_completion.set_sensitive(true);
                    match result {
                        Ok(imported_accounts) => {
                            match persist_otpauth_uri_list(
                                &unlocked_for_completion,
                                &directory_for_completion,
                                imported_accounts,
                            ) {
                                Ok(imported) => {
                                    if let (Some(stack), Some(window)) = (
                                        stack_for_completion.upgrade(),
                                        window_for_completion.upgrade(),
                                    ) {
                                        show_accounts_page(
                                            &stack,
                                            &window,
                                            directory_for_completion.clone(),
                                            unlocked_for_completion.clone(),
                                        );
                                        show_message_dialog(
                                            &window,
                                            "URI-list import complete",
                                            &format!(
                                                "Imported {imported} account(s) into the encrypted vault. The plaintext source file was not changed; delete it when no longer needed."
                                            ),
                                        );
                                    }
                                }
                                Err(message) => status_for_completion.set_text(&message),
                            }
                        }
                        Err(message) => status_for_completion.set_text(&message),
                    }
                    ControlFlow::Break
                }
                Err(TryRecvError::Empty) => ControlFlow::Continue,
                Err(TryRecvError::Disconnected) => {
                    import_for_completion.set_sensitive(true);
                    cancel_for_completion.set_sensitive(true);
                    status_for_completion.set_text(
                        "The plaintext URI-list import worker stopped unexpectedly.",
                    );
                    ControlFlow::Break
                }
            }
        });
    });

    replace_page(stack, "uri-list-import", &page);
}

fn load_otpauth_uri_list(path: &Path) -> Result<Vec<Account>, String> {
    let maximum_bytes = u64::try_from(MAX_OTPAUTH_URI_LIST_BYTES)
        .map_err(|_| "The URI-list size limit is invalid.".to_owned())?;
    let metadata =
        fs::metadata(path).map_err(|_| "The selected plaintext URI export could not be opened.")?;
    if !metadata.is_file() || metadata.len() > maximum_bytes {
        return Err("Choose a regular plaintext URI export no larger than 16 MiB.".to_owned());
    }
    let capacity = usize::try_from(metadata.len())
        .map_err(|_| "The selected URI export size is invalid.".to_owned())?;
    let read_limit = metadata
        .len()
        .checked_add(1)
        .ok_or_else(|| "The selected URI export size is invalid.".to_owned())?;
    let file =
        fs::File::open(path).map_err(|_| "The selected plaintext URI export could not be read.")?;
    let mut input = Zeroizing::new(Vec::with_capacity(capacity));
    let bytes_read = file
        .take(read_limit)
        .read_to_end(&mut input)
        .map_err(|_| "The selected plaintext URI export could not be read.")?;
    if bytes_read as u64 != metadata.len() {
        return Err(
            "The selected plaintext URI export changed while it was being read.".to_owned(),
        );
    }
    parse_otpauth_uri_list(&input).map_err(|error| error.to_string())
}

fn persist_otpauth_uri_list(
    unlocked: &Rc<RefCell<Option<AuthenticatedVault>>>,
    directory: &Path,
    imported: Vec<Account>,
) -> Result<usize, String> {
    let imported_count = imported.len();
    if imported_count == 0 {
        return Err("The plaintext URI export does not contain any accounts.".to_owned());
    }

    let mut guard = unlocked.borrow_mut();
    let vault = guard
        .as_mut()
        .ok_or_else(|| "The vault is locked. Unlock it before importing accounts.".to_owned())?;
    let existing = vault.accounts.encode().map_err(|error| error.to_string())?;
    let mut candidate = AccountDatabase::decode(&existing).map_err(|error| error.to_string())?;
    for account in imported {
        candidate
            .insert(account)
            .map_err(|error| error.to_string())?;
    }

    let store = VaultStore::open(directory).map_err(|error| error.to_string())?;
    let candidate_plaintext = candidate.encode().map_err(|error| error.to_string())?;
    let previous_plaintext = Zeroizing::new(vault.session.plaintext().to_vec());
    vault
        .session
        .replace_plaintext(candidate_plaintext)
        .map_err(|error| error.to_string())?;

    let encrypted = match vault.session.seal_current() {
        Ok(encrypted) => encrypted,
        Err(error) => {
            let _ = vault.session.replace_plaintext(previous_plaintext);
            return Err(error.to_string());
        }
    };
    if let Err(error) = store.save(&encrypted) {
        let _ = vault.session.replace_plaintext(previous_plaintext);
        return Err(error.to_string());
    }

    vault.accounts = candidate;
    Ok(imported_count)
}

fn show_backup_export_page(
    stack: &Stack,
    window: &ApplicationWindow,
    directory: PathBuf,
    unlocked: Rc<RefCell<Option<AuthenticatedVault>>>,
    path: PathBuf,
) {
    let page = GtkBox::new(Orientation::Vertical, 14);
    page.set_margin_top(28);
    page.set_margin_bottom(28);
    page.set_margin_start(28);
    page.set_margin_end(28);

    let title = Label::new(Some("Create encrypted backup"));
    title.add_css_class("title-1");
    title.set_xalign(0.0);
    let destination = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("backup file");
    let description = Label::new(Some(&format!(
        "The backup will be encrypted for {destination}. Choose a separate password; it is not your vault password. You will need it to restore this backup on another device."
    )));
    description.set_wrap(true);
    description.set_xalign(0.0);
    description.add_css_class("dim-label");
    page.append(&title);
    page.append(&description);

    let password = labeled_entry(&page, "Backup password", "Enter a new backup password");
    password.set_visibility(false);
    password.set_input_purpose(gtk::InputPurpose::Password);
    password.set_max_length(1024);
    password.set_widget_name("suika-secret-entry");
    let confirmation = labeled_entry(
        &page,
        "Confirm backup password",
        "Re-enter the backup password",
    );
    confirmation.set_visibility(false);
    confirmation.set_input_purpose(gtk::InputPurpose::Password);
    confirmation.set_max_length(1024);
    confirmation.set_widget_name("suika-secret-entry");

    let status = Label::new(None);
    status.set_wrap(true);
    status.set_xalign(0.0);
    let buttons = GtkBox::new(Orientation::Horizontal, 8);
    let cancel = Button::with_label("Cancel");
    let export = Button::with_label("Create backup");
    export.add_css_class("suggested-action");
    export.set_hexpand(true);
    buttons.append(&cancel);
    buttons.append(&export);

    page.append(&status);
    page.append(&buttons);

    let stack_for_cancel = stack.downgrade();
    let window_for_cancel = window.downgrade();
    let directory_for_cancel = directory.clone();
    let unlocked_for_cancel = unlocked.clone();
    let password_for_cancel = password.clone();
    let confirmation_for_cancel = confirmation.clone();
    cancel.connect_clicked(move |_| {
        password_for_cancel.set_text("");
        confirmation_for_cancel.set_text("");
        if let (Some(stack), Some(window)) =
            (stack_for_cancel.upgrade(), window_for_cancel.upgrade())
        {
            show_accounts_page(
                &stack,
                &window,
                directory_for_cancel.clone(),
                unlocked_for_cancel.clone(),
            );
        }
    });

    let status_for_export = status.clone();
    let export_for_export = export.clone();
    let password_for_export = password.clone();
    let confirmation_for_export = confirmation.clone();
    let directory_for_export = directory.clone();
    let unlocked_for_export = unlocked.clone();
    let stack_weak = stack.downgrade();
    let window_weak = window.downgrade();
    export.connect_clicked(move |_| {
        let password_bytes = Zeroizing::new(password_for_export.text().as_bytes().to_vec());
        let confirmation_bytes =
            Zeroizing::new(confirmation_for_export.text().as_bytes().to_vec());
        password_for_export.set_text("");
        confirmation_for_export.set_text("");

        if password_bytes.is_empty() {
            status_for_export.set_text("Choose a non-empty backup password.");
            return;
        }
        if password_bytes.len() > 1024 {
            status_for_export.set_text("The backup password exceeds the supported 1024-byte limit.");
            return;
        }
        if password_bytes.as_slice() != confirmation_bytes.as_slice() {
            status_for_export.set_text("The backup password confirmation does not match.");
            return;
        }

        let plaintext = {
            let borrowed = unlocked_for_export.borrow();
            match borrowed.as_ref() {
                Some(vault) => match vault.accounts.encode() {
                    Ok(plaintext) => plaintext,
                    Err(error) => {
                        status_for_export.set_text(&error.to_string());
                        return;
                    }
                },
                None => {
                    status_for_export.set_text("The vault is locked. Unlock it before creating a backup.");
                    return;
                }
            }
        };

        export_for_export.set_sensitive(false);
        status_for_export.set_text("Deriving the backup key and encrypting…");
        let path = path.clone();
        let directory_for_worker = directory_for_export.clone();
        let (sender, receiver) = mpsc::sync_channel(1);
        let worker = thread::Builder::new()
            .name("suika-backup-export".to_owned())
            .spawn(move || {
                let encrypted = Backup::create(
                    plaintext.as_slice(),
                    password_bytes.as_slice(),
                    KdfParams::PRODUCTION,
                );
                drop(plaintext);
                drop(password_bytes);
                let result = encrypted
                    .map_err(|error| error.to_string())
                    .and_then(|backup| {
                        let length = backup.len();
                        write_backup_file(&path, &backup, &directory_for_worker).map(|()| length)
                    });
                let _ = sender.send(result);
            });
        if let Err(error) = worker {
            export_for_export.set_sensitive(true);
            status_for_export.set_text(&format!("Could not start the backup worker: {error}"));
            return;
        }

        let status_for_completion = status_for_export.clone();
        let export_for_completion = export_for_export.clone();
        let directory_for_completion = directory_for_export.clone();
        let unlocked_for_completion = unlocked_for_export.clone();
        let stack_for_completion = stack_weak.clone();
        let window_for_completion = window_weak.clone();
        glib::source::timeout_add_local(Duration::from_millis(100), move || {
            match receiver.try_recv() {
                Ok(result) => {
                    export_for_completion.set_sensitive(true);
                    match result {
                        Ok(length) => {
                            if let (Some(stack), Some(window)) =
                                (stack_for_completion.upgrade(), window_for_completion.upgrade())
                            {
                                if unlocked_for_completion.borrow().is_some() {
                                    show_accounts_page(
                                        &stack,
                                        &window,
                                        directory_for_completion.clone(),
                                        unlocked_for_completion.clone(),
                                    );
                                }
                                show_message_dialog(
                                    &window,
                                    "Backup created",
                                    &format!(
                                        "The encrypted backup was written successfully ({length} bytes). Keep the separate password safe; it cannot be recovered."
                                    ),
                                );
                            }
                        }
                        Err(message) => status_for_completion.set_text(&message),
                    }
                    ControlFlow::Break
                }
                Err(TryRecvError::Empty) => ControlFlow::Continue,
                Err(TryRecvError::Disconnected) => {
                    export_for_completion.set_sensitive(true);
                    status_for_completion.set_text("The backup worker stopped unexpectedly.");
                    ControlFlow::Break
                }
            }
        });
    });

    replace_page(stack, "backup-export", &page);
}

fn show_backup_restore_page(
    stack: &Stack,
    window: &ApplicationWindow,
    directory: PathBuf,
    unlocked: Rc<RefCell<Option<AuthenticatedVault>>>,
    path: PathBuf,
) {
    let page = GtkBox::new(Orientation::Vertical, 14);
    page.set_margin_top(28);
    page.set_margin_bottom(28);
    page.set_margin_start(28);
    page.set_margin_end(28);

    let title = Label::new(Some("Restore encrypted backup"));
    title.add_css_class("title-1");
    title.set_xalign(0.0);
    let warning = Label::new(Some(
        "Restoring replaces every authenticator currently in your vault. It does not merge accounts. The existing account list remains unchanged unless the backup is fully authenticated, validated, and saved successfully.",
    ));
    warning.set_wrap(true);
    warning.set_xalign(0.0);
    warning.add_css_class("dim-label");
    let filename = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("backup file");
    let file_label = Label::new(Some(&format!("Selected file: {filename}")));
    file_label.set_xalign(0.0);
    page.append(&title);
    page.append(&warning);
    page.append(&file_label);

    let password = labeled_entry(
        &page,
        "Backup password",
        "Enter the password used for this backup",
    );
    password.set_visibility(false);
    password.set_input_purpose(gtk::InputPurpose::Password);
    password.set_max_length(1024);
    password.set_widget_name("suika-secret-entry");

    let status = Label::new(None);
    status.set_wrap(true);
    status.set_xalign(0.0);
    let buttons = GtkBox::new(Orientation::Horizontal, 8);
    let cancel = Button::with_label("Cancel");
    let restore = Button::with_label("Replace current accounts");
    restore.add_css_class("destructive-action");
    restore.set_hexpand(true);
    buttons.append(&cancel);
    buttons.append(&restore);

    page.append(&status);
    page.append(&buttons);

    let stack_for_cancel = stack.downgrade();
    let window_for_cancel = window.downgrade();
    let directory_for_cancel = directory.clone();
    let unlocked_for_cancel = unlocked.clone();
    let password_for_cancel = password.clone();
    cancel.connect_clicked(move |_| {
        password_for_cancel.set_text("");
        if let (Some(stack), Some(window)) =
            (stack_for_cancel.upgrade(), window_for_cancel.upgrade())
        {
            show_accounts_page(
                &stack,
                &window,
                directory_for_cancel.clone(),
                unlocked_for_cancel.clone(),
            );
        }
    });

    let status_for_restore = status.clone();
    let restore_for_restore = restore.clone();
    let cancel_for_restore = cancel.clone();
    let password_for_restore = password.clone();
    let directory_for_restore = directory.clone();
    let unlocked_for_restore = unlocked.clone();
    let stack_weak = stack.downgrade();
    let window_weak = window.downgrade();
    restore.connect_clicked(move |_| {
        let password_bytes = Zeroizing::new(password_for_restore.text().as_bytes().to_vec());
        password_for_restore.set_text("");
        if password_bytes.is_empty() {
            status_for_restore.set_text("Enter the backup password.");
            return;
        }
        if password_bytes.len() > 1024 {
            status_for_restore.set_text("The backup password exceeds the supported 1024-byte limit.");
            return;
        }

        restore_for_restore.set_sensitive(false);
        cancel_for_restore.set_sensitive(false);
        status_for_restore.set_text("Reading, authenticating, and validating the backup…");
        let path = path.clone();
        let (sender, receiver) = mpsc::sync_channel(1);
        let worker = thread::Builder::new()
            .name("suika-backup-restore".to_owned())
            .spawn(move || {
                let result = read_backup_file(&path)
                    .and_then(|backup| {
                        Backup::restore(&backup, password_bytes.as_slice())
                            .map_err(|error| error.to_string())
                    });
                let _ = sender.send(result);
            });
        if let Err(error) = worker {
            restore_for_restore.set_sensitive(true);
            cancel_for_restore.set_sensitive(true);
            status_for_restore.set_text(&format!("Could not start the restore worker: {error}"));
            return;
        }

        let status_for_completion = status_for_restore.clone();
        let restore_for_completion = restore_for_restore.clone();
        let cancel_for_completion = cancel_for_restore.clone();
        let directory_for_completion = directory_for_restore.clone();
        let unlocked_for_completion = unlocked_for_restore.clone();
        let stack_for_completion = stack_weak.clone();
        let window_for_completion = window_weak.clone();
        glib::source::timeout_add_local(Duration::from_millis(100), move || {
            match receiver.try_recv() {
                Ok(result) => {
                    restore_for_completion.set_sensitive(true);
                    cancel_for_completion.set_sensitive(true);
                    match result {
                        Ok(plaintext) => {
                            let persisted = persist_backup_restore(
                                &unlocked_for_completion,
                                &directory_for_completion,
                                plaintext,
                            );
                            match persisted {
                                Ok(restored_count) => {
                                    if let (Some(stack), Some(window)) =
                                        (stack_for_completion.upgrade(), window_for_completion.upgrade())
                                    {
                                        show_accounts_page(
                                            &stack,
                                            &window,
                                            directory_for_completion.clone(),
                                            unlocked_for_completion.clone(),
                                        );
                                        show_message_dialog(
                                            &window,
                                            "Backup restored",
                                            &format!(
                                                "Restored {restored_count} account(s). The previous account list was replaced."
                                            ),
                                        );
                                    }
                                }
                                Err(message) => status_for_completion.set_text(&message),
                            }
                        }
                        Err(message) => status_for_completion.set_text(&message),
                    }
                    ControlFlow::Break
                }
                Err(TryRecvError::Empty) => ControlFlow::Continue,
                Err(TryRecvError::Disconnected) => {
                    restore_for_completion.set_sensitive(true);
                    cancel_for_completion.set_sensitive(true);
                    status_for_completion.set_text("The backup restore worker stopped unexpectedly.");
                    ControlFlow::Break
                }
            }
        });
    });

    replace_page(stack, "backup-restore", &page);
}

fn persist_backup_restore(
    unlocked: &Rc<RefCell<Option<AuthenticatedVault>>>,
    directory: &Path,
    plaintext: Zeroizing<Vec<u8>>,
) -> Result<usize, String> {
    let candidate = AccountDatabase::decode(&plaintext).map_err(|error| error.to_string())?;
    let restored_count = candidate.len();
    let store = VaultStore::open(directory).map_err(|error| error.to_string())?;

    let mut guard = unlocked.borrow_mut();
    let vault = guard
        .as_mut()
        .ok_or_else(|| "The vault is locked. Unlock it before restoring a backup.".to_owned())?;
    let previous_plaintext = Zeroizing::new(vault.session.plaintext().to_vec());
    vault
        .session
        .replace_plaintext(plaintext)
        .map_err(|error| error.to_string())?;

    let encrypted = match vault.session.seal_current() {
        Ok(encrypted) => encrypted,
        Err(error) => {
            let _ = vault.session.replace_plaintext(previous_plaintext);
            return Err(error.to_string());
        }
    };
    if let Err(error) = store.save(&encrypted) {
        let _ = vault.session.replace_plaintext(previous_plaintext);
        return Err(error.to_string());
    }

    vault.accounts = candidate;
    Ok(restored_count)
}

fn read_backup_file(path: &Path) -> Result<Zeroizing<Vec<u8>>, String> {
    let metadata = fs::metadata(path).map_err(|_| "The selected backup could not be opened.")?;
    let maximum_bytes = u64::try_from(MAX_BACKUP_FILE_BYTES)
        .map_err(|_| "The backup size limit is invalid.".to_owned())?;
    let minimum_bytes = u64::try_from(suika_core::backup::MIN_BACKUP_FILE_BYTES)
        .map_err(|_| "The backup size limit is invalid.".to_owned())?;
    if !metadata.is_file() || metadata.len() > maximum_bytes {
        return Err(
            "Choose a regular encrypted backup within the supported size limit.".to_owned(),
        );
    }
    if metadata.len() < minimum_bytes {
        return Err("The selected backup is malformed or truncated.".to_owned());
    }

    let capacity = usize::try_from(metadata.len())
        .map_err(|_| "The selected backup size is invalid.".to_owned())?;
    let file = fs::File::open(path).map_err(|_| "The selected backup could not be read.")?;
    let mut input = Zeroizing::new(Vec::with_capacity(capacity));
    let read_limit = metadata
        .len()
        .checked_add(1)
        .ok_or_else(|| "The selected backup size is invalid.".to_owned())?;
    let bytes_read = file
        .take(read_limit)
        .read_to_end(&mut input)
        .map_err(|_| "The selected backup could not be read.")?;
    if bytes_read as u64 != metadata.len() {
        return Err("The selected backup changed while it was being read.".to_owned());
    }
    Backup::validate_serialized(&input).map_err(|error| error.to_string())?;
    Ok(input)
}

fn resolve_backup_destination(path: &Path, directory: &Path) -> Result<PathBuf, String> {
    if !path.is_absolute() {
        return Err("Choose an absolute backup file destination.".to_owned());
    }
    let parent = path
        .parent()
        .ok_or_else(|| "The selected backup destination has no parent directory.".to_owned())?;
    let filename = path
        .file_name()
        .ok_or_else(|| "The selected backup filename is invalid.".to_owned())?;
    let canonical_parent = fs::canonicalize(parent)
        .map_err(|_| "The selected backup destination directory could not be opened.")?;
    let destination = canonical_parent.join(filename);

    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err("Choose a backup destination that is not a symbolic link.".to_owned());
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err("The selected backup destination could not be inspected.".to_owned()),
    }

    let live_vault = fs::canonicalize(directory.join("vault.bin"))
        .map_err(|_| "The live encrypted vault could not be resolved.")?;
    if destination == live_vault {
        return Err(
            "The live vault file cannot be replaced by a backup. Choose a different filename."
                .to_owned(),
        );
    }

    Ok(destination)
}

fn write_backup_file(path: &Path, encrypted: &[u8], directory: &Path) -> Result<(), String> {
    if encrypted.len() > MAX_BACKUP_FILE_BYTES {
        return Err("The encrypted backup exceeds the supported size limit.".to_owned());
    }
    let destination = resolve_backup_destination(path, directory)?;
    let parent = destination
        .parent()
        .ok_or_else(|| "The selected backup destination has no parent directory.".to_owned())?;
    let filename = destination
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| "The selected backup filename is invalid.".to_owned())?;

    let mut last_error = None;
    for _ in 0..8 {
        let mut random = [0_u8; 16];
        getrandom::fill(&mut random)
            .map_err(|_| "The operating system random source is unavailable.")?;
        let temporary = parent.join(format!(
            ".{filename}.suika-backup-{}-{:032x}.tmp",
            std::process::id(),
            u128::from_ne_bytes(random)
        ));
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true).mode(0o600);
        let mut file = match options.open(&temporary) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                last_error = Some(error);
                continue;
            }
            Err(error) => return Err(error.to_string()),
        };

        let result = file
            .write_all(encrypted)
            .and_then(|()| file.sync_all())
            .map_err(|error| error.to_string());
        drop(file);
        if let Err(message) = result {
            let _ = fs::remove_file(&temporary);
            return Err(message);
        }
        if let Err(error) = fs::rename(&temporary, &destination) {
            let _ = fs::remove_file(&temporary);
            return Err(error.to_string());
        }
        fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| {
                format!("Backup file was written, but its directory could not be synced: {error}")
            })?;
        return Ok(());
    }

    Err(last_error
        .map(|error| format!("Could not create a unique temporary backup file: {error}"))
        .unwrap_or_else(|| "Could not create a temporary backup file.".to_owned()))
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


fn refresh_selected_account(
    selected_id: Option<[u8; 16]>,
    unlocked: &Rc<RefCell<Option<AuthenticatedVault>>>,
    issuer: &Label,
    account_label: &Label,
    code: &Label,
    countdown: &Label,
    copy: &Button,
    advance: &Button,
    edit: &Button,
    remove: &Button,
) {
    let Some(id) = selected_id else {
        issuer.set_text("Select an account");
        account_label.set_text("Choose an account from the list to view its one-time password.");
        code.set_text("------");
        countdown.set_text("");
        copy.set_visible(false);
        advance.set_visible(false);
        edit.set_visible(false);
        remove.set_visible(false);
        return;
    };

    let guard = unlocked.borrow();
    let Some(vault) = guard.as_ref() else {
        issuer.set_text("Vault locked");
        account_label.set_text("Unlock the vault to view accounts.");
        code.set_text("------");
        countdown.set_text("");
        copy.set_visible(false);
        advance.set_visible(false);
        edit.set_visible(false);
        remove.set_visible(false);
        return;
    };

    let Some(account) = vault
        .accounts
        .accounts()
        .iter()
        .find(|account| account.id() == &id)
    else {
        issuer.set_text("Account unavailable");
        account_label.set_text("This account is no longer in the vault.");
        code.set_text("------");
        countdown.set_text("");
        copy.set_visible(false);
        advance.set_visible(false);
        edit.set_visible(false);
        remove.set_visible(false);
        return;
    };

    let display_issuer = if account.issuer().is_empty() {
        account.label()
    } else {
        account.issuer()
    };
    issuer.set_text(display_issuer);
    account_label.set_text(account.label());
    let now = unix_time();
    code.set_text(
        &account
            .generate_code(now)
            .unwrap_or_else(|_| "------".to_owned()),
    );

    match account.mode() {
        AccountMode::Totp { period_seconds } => {
            let remaining = period_seconds - (now % period_seconds);
            countdown.set_text(&format!("Refreshes in {remaining} seconds"));
            copy.set_visible(true);
            advance.set_visible(false);
        }
        AccountMode::Hotp { counter } => {
            countdown.set_text(&format!("HOTP • Counter {counter}"));
            copy.set_visible(false);
            advance.set_visible(true);
        }
    }

    edit.set_visible(true);
    remove.set_visible(true);
}

fn show_accounts_page(
    stack: &Stack,
    window: &ApplicationWindow,
    directory: PathBuf,
    unlocked: Rc<RefCell<Option<AuthenticatedVault>>>,
) {
    for name in [
        "add-account",
        "edit-account",
        "aegis-import",
        "uri-list-import",
        "backup-export",
        "backup-restore",
    ] {
        if let Some(form_page) = stack.child_by_name(name) {
            stack.remove(&form_page);
        }
    }

    let page = GtkBox::new(Orientation::Vertical, 18);
    page.set_margin_top(22);
    page.set_margin_bottom(22);
    page.set_margin_start(22);
    page.set_margin_end(22);

    // Keep the global header deliberately small. Migration and backup tools
    // live in the overflow popover rather than competing with the account list.
    let header = GtkBox::new(Orientation::Horizontal, 12);
    let brand = GtkBox::new(Orientation::Vertical, 2);
    brand.set_hexpand(true);
    let app_title = Label::new(Some("SuikaAuthenticator"));
    app_title.add_css_class("title-1");
    app_title.set_xalign(0.0);
    let app_subtitle = Label::new(Some("Offline authenticator"));
    app_subtitle.add_css_class("dim-label");
    app_subtitle.set_xalign(0.0);
    brand.append(&app_title);
    brand.append(&app_subtitle);
    header.append(&brand);

    let lock = Button::with_label("Lock vault");
    let more = gtk::MenuButton::new();
    more.set_icon_name("open-menu-symbolic");
    more.set_tooltip_text(Some("Import, backup and restore"));

    let menu = gtk::Popover::new();
    let menu_content = GtkBox::new(Orientation::Vertical, 8);
    menu_content.set_margin_top(12);
    menu_content.set_margin_bottom(12);
    menu_content.set_margin_start(12);
    menu_content.set_margin_end(12);

    let import_heading = Label::new(Some("IMPORT"));
    import_heading.add_css_class("heading");
    import_heading.set_xalign(0.0);
    let import_aegis = Button::with_label("Import Aegis export");
    let import_uri_list = Button::with_label("Import URI list");
    menu_content.append(&import_heading);
    menu_content.append(&import_aegis);
    menu_content.append(&import_uri_list);
    menu_content.append(&gtk::Separator::new(Orientation::Horizontal));

    let backup_heading = Label::new(Some("BACKUP & RESTORE"));
    backup_heading.add_css_class("heading");
    backup_heading.set_xalign(0.0);
    let create_backup = Button::with_label("Create encrypted backup");
    let restore_backup = Button::with_label("Restore encrypted backup");
    let restore_hint = Label::new(Some("Restore replaces all current accounts; it does not merge them."));
    restore_hint.set_wrap(true);
    restore_hint.add_css_class("dim-label");
    restore_hint.set_xalign(0.0);
    menu_content.append(&backup_heading);
    menu_content.append(&create_backup);
    menu_content.append(&restore_backup);
    menu_content.append(&restore_hint);
    menu.set_child(Some(&menu_content));
    more.set_popover(Some(&menu));

    header.append(&lock);
    header.append(&more);
    page.append(&header);

    // Desktop split view: a compact account navigator on the left and the
    // selected account's OTP and management actions on the right.
    let content = GtkBox::new(Orientation::Horizontal, 16);
    content.set_vexpand(true);

    let sidebar = GtkBox::new(Orientation::Vertical, 10);
    sidebar.set_size_request(270, -1);
    sidebar.set_vexpand(true);
    let sidebar_header = GtkBox::new(Orientation::Horizontal, 8);
    let sidebar_title = Label::new(Some("Accounts"));
    sidebar_title.add_css_class("title-2");
    sidebar_title.set_hexpand(true);
    sidebar_title.set_xalign(0.0);
    let add = Button::with_label("Add account");
    add.add_css_class("suggested-action");
    sidebar_header.append(&sidebar_title);
    sidebar_header.append(&add);
    sidebar.append(&sidebar_header);

    let count = unlocked
        .borrow()
        .as_ref()
        .map_or(0, |vault| vault.accounts.len());
    let summary = Label::new(Some(&format!(
        "{count} saved {}",
        if count == 1 { "account" } else { "accounts" }
    )));
    summary.add_css_class("dim-label");
    summary.set_xalign(0.0);
    sidebar.append(&summary);

    let search = Entry::new();
    search.set_placeholder_text(Some("Search issuer or account…"));
    search.set_hexpand(true);
    sidebar.append(&search);

    let list = ListBox::new();
    list.set_selection_mode(gtk::SelectionMode::Single);
    list.set_activate_on_single_click(true);
    list.add_css_class("navigation-sidebar");

    let mut account_ids = Vec::new();
    let mut searchable_rows: Vec<(ListBoxRow, String)> = Vec::new();
    if let Some(vault) = unlocked.borrow().as_ref() {
        for account in vault.accounts.accounts() {
            let row_content = GtkBox::new(Orientation::Vertical, 3);
            row_content.set_margin_top(10);
            row_content.set_margin_bottom(10);
            row_content.set_margin_start(12);
            row_content.set_margin_end(12);

            let issuer = if account.issuer().is_empty() {
                account.label()
            } else {
                account.issuer()
            };
            let issuer_label = Label::new(Some(issuer));
            issuer_label.set_xalign(0.0);
            issuer_label.add_css_class("heading");

            let identity = Label::new(Some(account.label()));
            identity.set_xalign(0.0);
            identity.add_css_class("dim-label");

            let mode = match account.mode() {
                AccountMode::Totp { .. } => "TOTP",
                AccountMode::Hotp { .. } => "HOTP",
            };
            let mode_label = Label::new(Some(mode));
            mode_label.set_xalign(0.0);
            mode_label.add_css_class("dim-label");

            row_content.append(&issuer_label);
            row_content.append(&identity);
            row_content.append(&mode_label);

            let row = ListBoxRow::new();
            row.set_child(Some(&row_content));
            list.append(&row);
            account_ids.push(*account.id());
            searchable_rows.push((
                row,
                format!("{} {}", account.issuer(), account.label()).to_lowercase(),
            ));
        }
    }

    let scrolled = ScrolledWindow::new();
    scrolled.set_policy(gtk::PolicyType::Never, gtk::PolicyType::Automatic);
    scrolled.set_vexpand(true);
    scrolled.set_child(Some(&list));
    sidebar.append(&scrolled);
    content.append(&sidebar);
    content.append(&gtk::Separator::new(Orientation::Vertical));

    // The detail surface contains one selected account at a time. Keeping the
    // OTP non-selectable ensures copying always goes through the expiry-aware
    // clipboard action instead of manual text selection.
    let detail = GtkBox::new(Orientation::Vertical, 14);
    detail.set_hexpand(true);
    detail.set_vexpand(true);
    detail.set_valign(Align::Center);
    detail.set_halign(Align::Fill);
    detail.set_margin_top(28);
    detail.set_margin_bottom(28);
    detail.set_margin_start(28);
    detail.set_margin_end(28);
    detail.add_css_class("card");

    let detail_caption = Label::new(Some("ONE-TIME PASSWORD"));
    detail_caption.add_css_class("dim-label");
    detail_caption.set_xalign(0.5);
    let detail_issuer = Label::new(Some("Select an account"));
    detail_issuer.add_css_class("title-1");
    detail_issuer.set_xalign(0.5);
    detail_issuer.set_justify(gtk::Justification::Center);
    detail_issuer.set_wrap(true);
    let detail_account = Label::new(Some("Choose an account from the list to view its one-time password."));
    detail_account.add_css_class("dim-label");
    detail_account.set_xalign(0.5);
    detail_account.set_justify(gtk::Justification::Center);
    detail_account.set_wrap(true);

    let detail_code = Label::new(Some("------"));
    detail_code.add_css_class("title-1");
    detail_code.add_css_class("monospace");
    detail_code.set_xalign(0.5);
    detail_code.set_selectable(false);

    let detail_countdown = Label::new(None);
    detail_countdown.add_css_class("dim-label");
    detail_countdown.set_xalign(0.5);

    let actions = GtkBox::new(Orientation::Horizontal, 8);
    actions.set_halign(Align::Center);
    let copy = Button::with_label("Copy code");
    copy.add_css_class("suggested-action");
    let advance = Button::with_label("Copy & next");
    advance.add_css_class("suggested-action");
    let edit = Button::with_label("Edit");
    let remove = Button::with_label("Remove");
    remove.add_css_class("destructive-action");
    copy.set_visible(false);
    advance.set_visible(false);
    edit.set_visible(false);
    remove.set_visible(false);
    actions.append(&copy);
    actions.append(&advance);
    actions.append(&edit);
    actions.append(&remove);

    detail.append(&detail_caption);
    detail.append(&detail_issuer);
    detail.append(&detail_account);
    detail.append(&detail_code);
    detail.append(&detail_countdown);
    detail.append(&actions);
    content.append(&detail);
    page.append(&content);

    // Add-account and import/backup dialogs retain their existing transactional
    // flows; only their entry points are moved into the new layout.
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

    let stack_for_import = stack.downgrade();
    let window_for_import = window.downgrade();
    let directory_for_import = directory.clone();
    let unlocked_for_import = unlocked.clone();
    import_aegis.connect_clicked(move |_| {
        let file_dialog = gtk::FileDialog::builder()
            .title("Import Aegis export")
            .accept_label("Open")
            .modal(true)
            .build();
        let stack_weak = stack_for_import.clone();
        let window_weak = window_for_import.clone();
        let directory_for_file = directory_for_import.clone();
        let unlocked_for_file = unlocked_for_import.clone();
        if let Some(parent) = window_for_import.upgrade() {
            file_dialog.open(Some(&parent), None::<&gio::Cancellable>, move |result| {
                let Ok(file) = result else {
                    return;
                };
                let Some(path) = file.path() else {
                    if let Some(window) = window_weak.upgrade() {
                        show_message_dialog(
                            &window,
                            "Import unavailable",
                            "Choose a local Aegis JSON export.",
                        );
                    }
                    return;
                };
                if let (Some(stack), Some(window)) = (stack_weak.upgrade(), window_weak.upgrade()) {
                    show_aegis_import_page(
                        &stack,
                        &window,
                        directory_for_file.clone(),
                        unlocked_for_file.clone(),
                        path,
                    );
                }
            });
        }
    });

    let stack_for_uri_list = stack.downgrade();
    let window_for_uri_list = window.downgrade();
    let directory_for_uri_list = directory.clone();
    let unlocked_for_uri_list = unlocked.clone();
    import_uri_list.connect_clicked(move |_| {
        let file_dialog = gtk::FileDialog::builder()
            .title("Import plaintext URI list")
            .accept_label("Open")
            .modal(true)
            .build();
        let stack_weak = stack_for_uri_list.clone();
        let window_weak = window_for_uri_list.clone();
        let directory_for_file = directory_for_uri_list.clone();
        let unlocked_for_file = unlocked_for_uri_list.clone();
        if let Some(parent) = window_for_uri_list.upgrade() {
            file_dialog.open(Some(&parent), None::<&gio::Cancellable>, move |result| {
                let Ok(file) = result else {
                    return;
                };
                let Some(path) = file.path() else {
                    if let Some(window) = window_weak.upgrade() {
                        show_message_dialog(
                            &window,
                            "Import unavailable",
                            "Choose a local plaintext URI-list export.",
                        );
                    }
                    return;
                };
                if let (Some(stack), Some(window)) = (stack_weak.upgrade(), window_weak.upgrade()) {
                    show_otpauth_uri_list_import_page(
                        &stack,
                        &window,
                        directory_for_file.clone(),
                        unlocked_for_file.clone(),
                        path,
                    );
                }
            });
        }
    });

    let stack_for_backup_export = stack.downgrade();
    let window_for_backup_export = window.downgrade();
    let directory_for_backup_export = directory.clone();
    let unlocked_for_backup_export = unlocked.clone();
    create_backup.connect_clicked(move |_| {
        let file_dialog = gtk::FileDialog::builder()
            .title("Create encrypted backup")
            .accept_label("Save")
            .initial_name("SuikaAuthenticator.suikabak")
            .modal(true)
            .build();
        let stack_weak = stack_for_backup_export.clone();
        let window_weak = window_for_backup_export.clone();
        let directory_for_file = directory_for_backup_export.clone();
        let unlocked_for_file = unlocked_for_backup_export.clone();
        if let Some(parent) = window_for_backup_export.upgrade() {
            file_dialog.save(Some(&parent), None::<&gio::Cancellable>, move |result| {
                let Ok(file) = result else {
                    return;
                };
                let Some(path) = file.path() else {
                    if let Some(window) = window_weak.upgrade() {
                        show_message_dialog(
                            &window,
                            "Backup unavailable",
                            "Choose a local file destination for the encrypted backup.",
                        );
                    }
                    return;
                };
                if let (Some(stack), Some(window)) = (stack_weak.upgrade(), window_weak.upgrade()) {
                    show_backup_export_page(
                        &stack,
                        &window,
                        directory_for_file.clone(),
                        unlocked_for_file.clone(),
                        path,
                    );
                }
            });
        }
    });

    let stack_for_backup_restore = stack.downgrade();
    let window_for_backup_restore = window.downgrade();
    let directory_for_backup_restore = directory.clone();
    let unlocked_for_backup_restore = unlocked.clone();
    restore_backup.connect_clicked(move |_| {
        let file_dialog = gtk::FileDialog::builder()
            .title("Restore encrypted backup")
            .accept_label("Open")
            .modal(true)
            .build();
        let stack_weak = stack_for_backup_restore.clone();
        let window_weak = window_for_backup_restore.clone();
        let directory_for_file = directory_for_backup_restore.clone();
        let unlocked_for_file = unlocked_for_backup_restore.clone();
        if let Some(parent) = window_for_backup_restore.upgrade() {
            file_dialog.open(Some(&parent), None::<&gio::Cancellable>, move |result| {
                let Ok(file) = result else {
                    return;
                };
                let Some(path) = file.path() else {
                    if let Some(window) = window_weak.upgrade() {
                        show_message_dialog(
                            &window,
                            "Restore unavailable",
                            "Choose a local SuikaAuthenticator backup file.",
                        );
                    }
                    return;
                };
                if let (Some(stack), Some(window)) = (stack_weak.upgrade(), window_weak.upgrade()) {
                    show_backup_restore_page(
                        &stack,
                        &window,
                        directory_for_file.clone(),
                        unlocked_for_file.clone(),
                        path,
                    );
                }
            });
        }
    });

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

    let selected_id = Rc::new(Cell::new(None::<[u8; 16]>));
    let account_ids = Rc::new(account_ids);
    let selected_for_list = selected_id.clone();
    let unlocked_for_list = unlocked.clone();
    let selected_issuer = detail_issuer.clone();
    let selected_account = detail_account.clone();
    let selected_code = detail_code.clone();
    let selected_countdown = detail_countdown.clone();
    let selected_copy = copy.clone();
    let selected_advance = advance.clone();
    let selected_edit = edit.clone();
    let selected_remove = remove.clone();
    list.connect_row_selected(move |_, row| {
        let id = row.and_then(|row| {
            let index = row.index();
            if index < 0 {
                None
            } else {
                account_ids.get(index as usize).copied()
            }
        });
        selected_for_list.set(id);
        refresh_selected_account(
            id,
            &unlocked_for_list,
            &selected_issuer,
            &selected_account,
            &selected_code,
            &selected_countdown,
            &selected_copy,
            &selected_advance,
            &selected_edit,
            &selected_remove,
        );
    });

    let search_rows = searchable_rows;
    let list_for_search = list.clone();
    search.connect_changed(move |entry| {
        let query = entry.text().trim().to_lowercase();
        for (row, searchable_text) in &search_rows {
            row.set_visible(query.is_empty() || searchable_text.contains(&query));
        }

        let selected_is_hidden = list_for_search
            .selected_row()
            .is_none_or(|selected| !selected.is_visible());
        if selected_is_hidden {
            if let Some((first_visible, _)) =
                search_rows.iter().find(|(row, _)| row.is_visible())
            {
                list_for_search.select_row(Some(first_visible));
            } else {
                list_for_search.unselect_all();
            }
        }
    });

    let selected_for_copy = selected_id.clone();
    let code_for_copy = detail_code.clone();
    copy.connect_clicked(move |_| {
        if selected_for_copy.get().is_none() {
            return;
        }
        let value = code_for_copy.text().to_string();
        if value != "------" {
            if let Some(display) = gtk::gdk::Display::default() {
                copy_otp_to_clipboard(&display.clipboard(), value);
            }
        }
    });

    let selected_for_advance = selected_id.clone();
    let unlocked_for_advance = unlocked.clone();
    let directory_for_advance = directory.clone();
    let code_for_advance = detail_code.clone();
    let countdown_for_advance = detail_countdown.clone();
    advance.connect_clicked(move |_| {
        let Some(id) = selected_for_advance.get() else {
            return;
        };
        match advance_hotp_and_persist(&unlocked_for_advance, &directory_for_advance, &id) {
            Ok((used_code, next_code, next_counter)) => {
                code_for_advance.set_text(&next_code);
                countdown_for_advance.set_text(&format!("HOTP • Counter {next_counter}"));
                if let Some(display) = gtk::gdk::Display::default() {
                    copy_otp_to_clipboard(&display.clipboard(), used_code);
                }
            }
            Err(message) => {
                countdown_for_advance.set_text(&format!("Counter not advanced: {message}"));
            }
        }
    });

    let selected_for_edit = selected_id.clone();
    let stack_for_edit = stack.downgrade();
    let window_for_edit = window.downgrade();
    let directory_for_edit = directory.clone();
    let unlocked_for_edit = unlocked.clone();
    edit.connect_clicked(move |_| {
        let Some(id) = selected_for_edit.get() else {
            return;
        };
        if let (Some(stack), Some(window)) = (stack_for_edit.upgrade(), window_for_edit.upgrade()) {
            show_edit_account_page(
                &stack,
                &window,
                directory_for_edit.clone(),
                unlocked_for_edit.clone(),
                id,
            );
        }
    });

    let selected_for_remove = selected_id.clone();
    let stack_for_remove = stack.downgrade();
    let window_for_remove = window.downgrade();
    let directory_for_remove = directory.clone();
    let unlocked_for_remove = unlocked.clone();
    remove.connect_clicked(move |_| {
        let Some(id) = selected_for_remove.get() else {
            return;
        };
        if let (Some(stack), Some(window)) = (stack_for_remove.upgrade(), window_for_remove.upgrade()) {
            confirm_remove_account(
                &window,
                &stack,
                directory_for_remove.clone(),
                unlocked_for_remove.clone(),
                id,
            );
        }
    });

    if count == 0 {
        detail_issuer.set_text("No accounts yet");
        detail_account.set_text("Add an account or import an existing authenticator export to get started.");
        detail_code.set_text("—");
        detail_countdown.set_text("");
    } else if let Some(first_row) = list.row_at_index(0) {
        list.select_row(Some(&first_row));
    }

    let selected_for_timer = selected_id.clone();
    let unlocked_for_timer = unlocked.clone();
    let page_for_timer = page.clone();
    let issuer_for_timer = detail_issuer.clone();
    let account_for_timer = detail_account.clone();
    let code_for_timer = detail_code.clone();
    let countdown_for_timer = detail_countdown.clone();
    let copy_for_timer = copy.clone();
    let advance_for_timer = advance.clone();
    let edit_for_timer = edit.clone();
    let remove_for_timer = remove.clone();
    glib::source::timeout_add_seconds_local(1, move || {
        if count == 0 || !page_for_timer.is_mapped() {
            return ControlFlow::Break;
        }

        refresh_selected_account(
            selected_for_timer.get(),
            &unlocked_for_timer,
            &issuer_for_timer,
            &account_for_timer,
            &code_for_timer,
            &countdown_for_timer,
            &copy_for_timer,
            &advance_for_timer,
            &edit_for_timer,
            &remove_for_timer,
        );
        ControlFlow::Continue
    });

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
    use std::sync::atomic::{AtomicU64, Ordering};

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
    fn linux_file_reader_restores_the_shared_portable_backup_fixture() {
        let fixture_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../crates/suika-core/tests/fixtures/portable_backup_v1.suikabak");
        let encrypted = read_backup_file(&fixture_path)
            .expect("Linux file reader should accept the shared backup fixture");
        let plaintext = Backup::restore(&encrypted, b"portable-backup-fixture-password")
            .expect("Linux should restore the shared portable backup fixture");
        let accounts = AccountDatabase::decode(&plaintext)
            .expect("shared fixture account database should decode");

        assert_eq!(accounts.len(), 2);
        assert_eq!(accounts.accounts()[0].issuer(), "CrossPlatform");
        assert_eq!(accounts.accounts()[0].label(), "fixture-totp");
        assert_eq!(
            accounts.accounts()[0].mode(),
            AccountMode::Totp { period_seconds: 60 }
        );
        assert_eq!(accounts.accounts()[1].issuer(), "CrossPlatform");
        assert_eq!(accounts.accounts()[1].label(), "fixture-hotp");
        assert_eq!(
            accounts.accounts()[1].mode(),
            AccountMode::Hotp { counter: 9 }
        );
    }

    #[test]
    fn backup_export_writes_a_private_file() {
        static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);
        let directory = loop {
            let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let candidate = std::env::temp_dir().join(format!(
                "suika-backup-permissions-test-{}-{sequence}",
                std::process::id()
            ));
            match fs::create_dir(&candidate) {
                Ok(()) => break candidate,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("test directory should be created: {error}"),
            }
        };
        fs::write(directory.join("vault.bin"), b"live vault contents")
            .expect("test vault file should be written");

        let destination = directory.join("backup.suikabak");
        write_backup_file(&destination, b"encrypted backup bytes", &directory)
            .expect("encrypted backup should be written");
        let metadata =
            fs::metadata(&destination).expect("backup file should be present after export");
        let permissions = metadata.permissions();
        use std::os::unix::fs::PermissionsExt;
        let mode = permissions.mode() & 0o777;

        assert_eq!(mode & 0o600, 0o600, "owner read/write access is required");
        assert_eq!(mode & 0o077, 0, "group/other access must be denied");
        assert_eq!(
            fs::read(&destination).expect("encrypted backup should be readable"),
            b"encrypted backup bytes"
        );

        fs::remove_dir_all(&directory).expect("test directory should be removed");
    }

    #[test]
    fn backup_export_cannot_replace_the_live_vault_file() {
        static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);
        let directory = loop {
            let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let candidate = std::env::temp_dir().join(format!(
                "suika-backup-path-test-{}-{sequence}",
                std::process::id()
            ));
            match fs::create_dir(&candidate) {
                Ok(()) => break candidate,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("test directory should be created: {error}"),
            }
        };
        let vault_path = directory.join("vault.bin");
        fs::write(&vault_path, b"live vault contents").expect("test vault file should be written");

        let result = write_backup_file(&vault_path, b"encrypted backup bytes", &directory);
        assert!(result.is_err());
        assert_eq!(
            fs::read(&vault_path).expect("live vault should remain readable"),
            b"live vault contents"
        );

        fs::remove_dir_all(&directory).expect("test directory should be removed");
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
