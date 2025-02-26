package interfaces.callbacks.impl;

import interfaces.callbacks.JavaAuthorizeCb;
import jnr.ffi.Pointer;
import mapper.NpTokenMapper;
import models.NeuropilNode;
import models.NpToken;
import utils.NeuropilUtils;

public class JavaAuthorizeCbImpl implements JavaAuthorizeCb {
    @Override
    public boolean javaAuthorizeCb(Pointer context, Pointer token) {
        NeuropilNode myself = NeuropilUtils.fromContext(context);
        NpTokenMapper mapper = new NpTokenMapper();
        NpToken npToken = mapper.convert(token);
        return NeuropilUtils.executeCallback(myself.getUserAuthorizeCb(), myself, npToken);

    }
}
