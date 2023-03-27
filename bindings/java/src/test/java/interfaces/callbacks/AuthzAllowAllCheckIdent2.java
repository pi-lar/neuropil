package interfaces.callbacks;

import jnr.ffi.annotations.Delegate;
import models.NeuropilNode;
import models.NpToken;

public interface AuthzAllowAllCheckIdent2 {

    @Delegate
    public boolean authzAllowAllCheckIdent2(NeuropilNode node, NpToken token);
}
