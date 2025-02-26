package enums;

import jnr.ffi.util.EnumMapper;

public enum NpMxRole implements EnumMapper.IntegerEnum {

    NP_MX_PROVIDER(0),
    NP_MX_CONSUMER(1),
    NP_MX_PROSUMER(2);

    private final int value;

    NpMxRole(int value) {
        this.value = value;
    }

    @Override
    public int intValue() {
        return value;
    }
}