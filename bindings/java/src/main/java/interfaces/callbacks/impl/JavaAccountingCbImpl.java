package interfaces.callbacks.impl;

import interfaces.callbacks.JavaAccountingCb;
import jnr.ffi.Pointer;
import mapper.NpTokenMapper;
import models.NeuropilNode;
import models.NpToken;
import utils.NeuropilUtils;

public class JavaAccountingCbImpl implements JavaAccountingCb {
    @Override
    public boolean javaAccountingCb(Pointer context, Pointer token) {
        NeuropilNode myself = NeuropilUtils.fromContext(context);
        NpTokenMapper mapper = new NpTokenMapper();
        NpToken npToken = mapper.convert(token);
        return NeuropilUtils.executeCallback(myself.getUserAccountingCb(), myself, npToken);


    }
}
