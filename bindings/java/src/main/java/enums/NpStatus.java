package enums;

import jnr.ffi.util.EnumMapper;

public enum NpStatus implements EnumMapper.IntegerEnum {

    NP_ERROR(0),
    NP_UNINITIALIZED(1),
    NP_RUNNING(2),
    NP_STOPPED(3),
    NP_SHUTDOWN(4);


    private final int value;

    NpStatus(int value) {
        this.value = value;
    }

    @Override
    public int intValue() {
        return value;
    }
}
