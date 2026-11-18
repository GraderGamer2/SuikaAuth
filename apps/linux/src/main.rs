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
use suika_core::accounts::{Account, AccountDatabase, AccountMode};
use suika_core::crypto::KdfParams;
use suika_core::otp::OtpAlgorithm;
use suika_core::storage::{StorageError, VaultStore};
use suika_core::vault::{Vault, VaultError, VaultSession};
use zeroize::Zeroizing;

const APP_ID: &str = "org.suika.SuikaAuthenticator";
const DATA_DIRECTORY: &str = ".SuikaAuthenticator";

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
                _session: session,
                accounts: database,
            })
        }
    }
}

fn labeled_entry(parent: &GtkBox, label_text: &str, placeholder: &str) -> Entry {
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
    entry
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
        "Enter the account details and its Base32 TOTP secret. The secret is encrypted before it is written to disk.",
    ));
    description.set_wrap(true);
    description.set_xalign(0.0);
    description.add_css_class("dim-label");

    let issuer = labeled_entry(&page, "Issuer (optional)", "Example: GitHub");
    issuer.set_max_length(256);

    let label = labeled_entry(&page, "Account name", "Example: name@example.com");
    label.set_max_length(256);

    let secret = labeled_entry(&page, "TOTP secret (Base32)", "Paste the secret key");
    secret.set_visibility(false);
    secret.set_input_purpose(gtk::InputPurpose::Password);
    secret.set_max_length(208);

    let algorithm = labeled_entry(&page, "HMAC algorithm", "SHA1, SHA256, or SHA512");
    algorithm.set_text("SHA1");
    algorithm.set_max_length(6);

    let digits = labeled_entry(&page, "Code digits", "6, 7, or 8");
    digits.set_text("6");
    digits.set_max_length(1);

    let period = labeled_entry(&page, "Time period (seconds)", "30");
    period.set_text("30");
    period.set_max_length(5);

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
    back.connect_clicked(move |_| {
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
    let algorithm_for_save = algorithm.clone();
    let digits_for_save = digits.clone();
    let period_for_save = period.clone();
    let status_for_save = status.clone();
    let save_for_save = save.clone();

    save.connect_clicked(move |_| {
        let issuer_value = issuer_for_save.text().trim().to_owned();
        let label_value = label_for_save.text().trim().to_owned();
        let secret_value = Zeroizing::new(secret_for_save.text().to_string());
        secret_for_save.set_text("");

        let algorithm_value = match algorithm_for_save.text().trim().to_ascii_uppercase().as_str() {
            "SHA1" => OtpAlgorithm::Sha1,
            "SHA256" => OtpAlgorithm::Sha256,
            "SHA512" => OtpAlgorithm::Sha512,
            _ => {
                status_for_save.set_text("Choose SHA1, SHA256, or SHA512.");
                return;
            }
        };
        let digits_value = match digits_for_save.text().trim().parse::<u8>() {
            Ok(value @ 6..=8) => value,
            _ => {
                status_for_save.set_text("Code length must be 6, 7, or 8 digits.");
                return;
            }
        };
        let period_value = match period_for_save.text().trim().parse::<u64>() {
            Ok(value @ 1..=86_400) => value,
            _ => {
                status_for_save.set_text("TOTP period must be between 1 and 86400 seconds.");
                return;
            }
        };
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
                status_for_save.set_text(&message);
                return;
            }
        };

        let account = match Account::new_totp(
            issuer_value,
            label_value,
            secret_bytes,
            algorithm_value,
            digits_value,
            period_value,
        ) {
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

fn persist_vault(vault: &mut AuthenticatedVault, directory: &Path) -> Result<(), String> {
    let plaintext = vault
        .accounts
        .encode()
        .map_err(|error| error.to_string())?;
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

fn decode_base32(input: &str) -> Result<Zeroizing<Vec<u8>>, String> {
    let compact: String = input
        .chars()
        .filter(|character| !character.is_ascii_whitespace() && *character != '-')
        .collect();

    if compact.is_empty() {
        return Err("Enter a Base32 secret.".to_owned());
    }

    let first_padding = compact.find('=').unwrap_or(compact.len());
    let data = &compact[..first_padding];
    let padding = &compact[first_padding..];

    if padding.chars().any(|character| character != '=') {
        return Err("The Base32 secret contains invalid padding.".to_owned());
    }
    if data.is_empty() || data.len() > 206 {
        return Err("The Base32 secret has an unsupported length.".to_owned());
    }

    let expected_padding = match data.len() % 8 {
        0 => 0,
        2 => 6,
        4 => 4,
        5 => 3,
        7 => 1,
        _ => return Err("The Base32 secret has an invalid length.".to_owned()),
    };
    if !padding.is_empty()
        && (compact.len() % 8 != 0 || padding.len() != expected_padding)
    {
        return Err("The Base32 secret has invalid padding.".to_owned());
    }

    let mut output = Zeroizing::new(Vec::with_capacity(data.len() * 5 / 8));
    let mut accumulator = 0_u32;
    let mut bits = 0_u8;

    for character in data.chars() {
        let value = match character.to_ascii_uppercase() {
            'A'..='Z' => character.to_ascii_uppercase() as u8 - b'A',
            '2'..='7' => character as u8 - b'2' + 26,
            _ => return Err("The Base32 secret contains an invalid character.".to_owned()),
        };

        accumulator = (accumulator << 5) | u32::from(value);
        bits += 5;

        if bits >= 8 {
            bits -= 8;
            output.push(((accumulator >> bits) & 0xFF) as u8);
            accumulator &= (1_u32 << bits) - 1;
        }
    }

    if bits > 0 && accumulator != 0 {
        return Err("The Base32 secret has non-zero unused trailing bits.".to_owned());
    }
    if output.is_empty() || output.len() > 128 {
        return Err("The decoded Base32 secret must be 1 to 128 bytes.".to_owned());
    }

    Ok(output)
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
        if let (Some(stack), Some(window)) =
            (stack_for_add.upgrade(), window_for_add.upgrade())
        {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base32_decodes_rfc4648_vectors() {
        assert_eq!(decode_base32("MY======").expect("valid Base32").as_slice(), b"f");
        assert_eq!(
            decode_base32("MZXQ====").expect("valid Base32").as_slice(),
            b"fo"
        );
        assert_eq!(
            decode_base32("MZXW6===")
                .expect("valid Base32")
                .as_slice(),
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

fn unix_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
