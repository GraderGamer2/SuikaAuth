package org.suika.suikaauthenticator;

/**
 * Narrow JNI boundary. Password, export, URI, and encoded secret byte arrays
 * are cleared by the caller after each synchronous native operation.
 */
final class NativeBridge {
    static {
        System.loadLibrary("suika_authenticator_android");
    }

    private NativeBridge() {}

    static native boolean nativeHasVault(String appPrivateRoot);
    static native long nativeCreateVault(String appPrivateRoot, byte[] password);
    static native long nativeUnlockVault(String appPrivateRoot, byte[] password);
    static native long nativeUnlockVaultWithDeviceKey(String appPrivateRoot, byte[] wrappingKey);
    static native byte[] nativeExportDeviceUnlockKey(long sessionHandle);
    static native void nativeLockVault(long sessionHandle);
    static native String[] nativeListAccounts(long sessionHandle);
    static native void nativeImportOtpAuthUri(long sessionHandle, byte[] encodedUri);
    static native String nativeImportAegisExport(
        long sessionHandle,
        byte[] encodedExport,
        byte[] password
    );
    static native void nativeAddTotp(
        long sessionHandle,
        String issuer,
        String label,
        byte[] encodedSecret,
        int algorithm,
        int digits,
        long periodSeconds
    );
    static native void nativeUpdateAccount(
        long sessionHandle,
        String accountIdHex,
        String issuer,
        String label,
        byte[] replacementSecret
    );
    static native void nativeRemoveAccount(long sessionHandle, String accountIdHex);
    static native String nativeConsumeHotp(long sessionHandle, String accountIdHex);
}
