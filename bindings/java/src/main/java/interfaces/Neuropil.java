package interfaces;

import enums.NpReturn;
import interfaces.callbacks.JavaAccountingCb;
import interfaces.callbacks.JavaAuthenticateCb;
import interfaces.callbacks.JavaAuthorizeCb;
import jnr.ffi.Pointer;
import mapper.NpTokenMapper;
import models.NpId;
import models.NpMxProperties;
import models.NpSettings;
import models.NpToken;

public interface Neuropil {
    String np_error_str(Integer i);
    NpSettings np_default_settings(NpSettings np_settings);
    Pointer np_new_context(NpSettings settings);
    int np_listen(Pointer context, String protocol, String host, int port, String dnsName);
    int np_get_address(Pointer context, byte[] address, int max);

    int np_join(Pointer context, String connectString);

    int np_get_status(Pointer context);

    boolean np_has_joined(Pointer context);

    int np_run(Pointer context, double duration);

    int np_destroy(Pointer context, boolean gracefully);

    int np_set_authenticate_cb(Pointer context, JavaAuthenticateCb javaAuthenticateCb);

    int np_set_authorize_cb(Pointer context, JavaAuthorizeCb javaAuthorizeCb);

    int np_set_accounting_cb(Pointer context, JavaAccountingCb javaAccountingCb);

    NpToken np_new_identity_java(Pointer context, double expiresAt, byte[] internalSecretKey);

    int np_use_identity_java(Pointer context, NpToken npToken);

    void np_set_userdata(Pointer context, Pointer userdata);

    Pointer np_get_userdata(Pointer context);

    int np_token_fingerprint_java(Pointer context, NpToken npToken, Boolean checkAttributes, byte[] npId);

    NpMxProperties np_get_mx_properties(Pointer context,byte [] subject);

    String np_id_str_java(byte[] str, byte[] id);




}
