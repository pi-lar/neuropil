package interfaces.callbacks;

import jnr.ffi.Pointer;
import jnr.ffi.annotations.Delegate;

public interface JavaAuthenticateCb {
    @Delegate
    public boolean javaAuthenticateCb(Pointer context, Pointer token);
}
