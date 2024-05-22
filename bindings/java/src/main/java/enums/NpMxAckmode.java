package enums;

import jnr.ffi.util.EnumMapper;

public enum NpMxAckmode implements EnumMapper.IntegerEnum {

    NP_MX_ACK_NONE(0),
    NP_MX_ACK_DESTINATION(1),
    NP_MX_ACK_CLIENT(2);

    private final int value;

    NpMxAckmode(int value) {
        this.value = value;
    }

    @Override
    public int intValue() {
        return value;
    }
}