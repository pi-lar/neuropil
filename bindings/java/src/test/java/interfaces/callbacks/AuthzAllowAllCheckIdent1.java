package interfaces.callbacks;

import jnr.ffi.Pointer;
import jnr.ffi.annotations.Delegate;
import models.NeuropilNode;
import models.NpToken;

public interface AuthzAllowAllCheckIdent1 {

    @Delegate
    public boolean authzAllowAllCheckIdent1(NeuropilNode node, NpToken token);
}
