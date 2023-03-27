package models;

import enums.NpMxAckmode;
import enums.NpMxRole;
import jnr.ffi.Runtime;
import jnr.ffi.Struct;

public class NpMxProperties extends Struct {

    public NpMxRole npMxRole;
    public NpMxAckmode npMxAckmode;

    public int maxRetry;

    public NpMxProperties(Runtime runtime) {
        super(runtime);
    }

    public NpMxRole getNpMxRole() {
        return npMxRole;
    }

    public void setNpMxRole(NpMxRole npMxRole) {
        this.npMxRole = npMxRole;
    }

    public NpMxAckmode getNpMxAckmode() {
        return npMxAckmode;
    }

    public void setNpMxAckmode(NpMxAckmode npMxAckmode) {
        this.npMxAckmode = npMxAckmode;
    }

    public int getMaxRetry() {
        return maxRetry;
    }

    public void setMaxRetry(int maxRetry) {
        this.maxRetry = maxRetry;
    }
}
