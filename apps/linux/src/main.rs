//! Native GTK4 frontend for SuikaAuthenticator.
//!
//! The shared core owns vault and account cryptography. This binary owns only
//! GTK presentation and the Linux application-directory choice.

use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::mpsc::{self, TryRecvError};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use gtk::glib::{self, ControlFlow};
use gtk::prelude::*;
use gtk::{
    Align, Application, ApplicationWindow, Box as GtkBox, Button, Entry, Label, ListBox,
    ListBoxRow, Orientation, ScrolledWindow, Spinner, Stack,
};
use suika_core::accounts::{AccountDatabase, AccountMode};
use suika_core::crypto::KdfParams;
use suika_core::storage::{StorageError, VaultStore};
use suika_core::vault::{Vault, VaultError, VaultSession};
use zeroize::Zeroizing;

const APP_ID: &str = "org.suika.SuikaAuthenticator";
const DATA_DIRECTORY: &str = ".SuikaAuthenticator";

struct AuthenticatedVault {
    // Kept alive for the complete unlocked session. Dropping this clears the
    // decrypted account database and the in-memory data-encryption key.
    _session: VaultSession,
    accounts: AccountDatabase,
}

#[derive(Clone, Copy)]
enum AuthMode {
    Create,
    Unlock,
}

fn main() -> glib::ExitCode {
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

    let stack = Stack::new();
    stack.set_transition_type(gtk::StackTransitionType::Crossfade);
    window.set_child(Some(&stack));

    let unlocked = Rc::new(RefCell::new(None::<AuthenticatedVault>));
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

    show_auth_page(&stack, &window, directory, mode, unlocked);
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
    stack.add_named(page, name);
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
                _session: session,
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
                _session: session,
                accounts: database,
            })
        }
    }
}

struct AccountRowWidgets {
    id: [u8; 16],
    code: Label,
    countdown: Label,
}

fn show_accounts_page(
    stack: &Stack,
    window: &ApplicationWindow,
    directory: PathBuf,
    unlocked: Rc<RefCell<Option<AuthenticatedVault>>>,
) {
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
    let lock = Button::with_label("Lock");
    header.append(&title);
    header.append(&lock);
    page.append(&header);

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

    let list = ListBox::new();
    list.set_selection_mode(gtk::SelectionMode::None);
    list.add_css_class("boxed-list");

    let mut row_widgets = Vec::new();
    if let Some(vault) = unlocked.borrow().as_ref() {
        if vault.accounts.is_empty() {
            let empty = GtkBox::new(Orientation::Vertical, 8);
            empty.set_margin_top(32);
            empty.set_margin_bottom(32);
            let empty_title = Label::new(Some("No accounts yet"));
            empty_title.add_css_class("title-2");
            let empty_hint = Label::new(Some(
                "Your encrypted vault is ready. Manual TOTP and HOTP enrollment is the next Linux frontend step.",
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

                row_content.append(&identity);
                row_content.append(&copy);

                let row = ListBoxRow::new();
                row.set_child(Some(&row_content));
                row.set_activatable(false);
                row.set_selectable(false);
                list.append(&row);

                row_widgets.push(AccountRowWidgets {
                    id: *account.id(),
                    code,
                    countdown,
                });
            }
        }
    }

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
        unlocked_for_lock.borrow_mut().take();
        if let (Some(stack), Some(window)) = (stack_for_lock.upgrade(), window_for_lock.upgrade()) {
            show_auth_page(
                &stack,
                &window,
                directory_for_lock.clone(),
                AuthMode::Unlock,
                unlocked_for_lock.clone(),
            );
        }
    });

    if !row_widgets.is_empty() {
        let unlocked_for_timer = unlocked.clone();
        glib::source::timeout_add_seconds_local(1, move || {
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
