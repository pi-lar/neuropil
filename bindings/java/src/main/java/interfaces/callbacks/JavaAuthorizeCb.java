package interfaces.callbacks;

import jnr.ffi.Pointer;
import jnr.ffi.annotations.Delegate;

public interface JavaAuthorizeCb {
    @Delegate
    public boolean javaAuthorizeCb(Pointer context, Pointer token);
}
