package enums;

import jnr.ffi.util.EnumMapper;

public enum NpReturn implements EnumMapper.IntegerEnum {

    NP_OK(0),
    NP_UNKNOWN_ERROR(1),
    NP_NOT_IMPLEMENTED(2),
    NP_NETWORK_ERROR(3),
    NP_INVALID_ARGUMENT(4),
    NP_INVALID_OPERATION(5),
    NP_STARTUP(6);

    private final int value;

    NpReturn(int value) {
        this.value = value;
    }

    @Override
    public int intValue() {
        return value;
    }
}
