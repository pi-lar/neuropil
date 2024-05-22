package interfaces.callbacks.impl;

import enums.NpLimits;
import interfaces.callbacks.JavaAuthenticateCb;
import jnr.ffi.Pointer;
import mapper.NpTokenMapper;
import models.NeuropilNode;
import models.NpToken;
import utils.NeuropilUtils;

import java.nio.charset.Charset;

public class JavaAuthenticateCbImpl implements JavaAuthenticateCb {

    @Override
    public boolean javaAuthenticateCb(Pointer context, Pointer token) {
        NeuropilNode myself = NeuropilUtils.fromContext(context);
        NpToken npToken =  NpTokenMapper.convert(token);
        return NeuropilUtils.executeCallback(myself.getUserAuthenticateCb(), myself, npToken);

    }
}
