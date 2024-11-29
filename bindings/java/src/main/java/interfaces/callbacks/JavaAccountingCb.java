package interfaces.callbacks;

import jnr.ffi.Pointer;
import jnr.ffi.annotations.Delegate;
import models.NpToken;

public interface JavaAccountingCb {
    @Delegate
    public boolean javaAccountingCb(Pointer context, Pointer token);
}
