package enums;

import jnr.ffi.util.EnumMapper;

public enum NpLimits  implements EnumMapper.IntegerEnum {

    NP_SECRET_KEY_BYTES(64),
    NP_SIGNATURE_BYTES(64),
    NP_PUBLIC_KEY_BYTES(32),
    NP_FINGERPRINT_BYTES(32),
    NP_UUID_BYTES(37),
    NP_EXTENSION_BYTES(10240);

    private final int value;

    NpLimits(int value) {
        this.value = value;
    }

    @Override
    public int intValue() {
        return value;
    }
}
