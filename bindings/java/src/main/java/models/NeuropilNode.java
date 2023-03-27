package models;

import common.LoadLibrary;
import enums.NpLimits;
import enums.NpReturn;
import interfaces.Neuropil;
import interfaces.callbacks.impl.JavaAccountingCbImpl;
import interfaces.callbacks.impl.JavaAuthenticateCbImpl;
import interfaces.callbacks.impl.JavaAuthorizeCbImpl;
import jnr.ffi.*;
import common.NeuropilObjectManager;
import mapper.NpTokenMapper;
import utils.NeuropilUtils;

import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Objects;

public class NeuropilNode {

    private int port;
    private String host;
    private String proto;
    private String dnsName;
    private boolean autoRun;
    private boolean destroyed;
    private String logWriteFn;

    private Pointer userdata;
    private Method userAuthenticateCb; //Armazena o metodo que deverá ser executado após o callback
    private Method userAuthorizeCb; //Armazena o metodo que deverá ser executado após o callback
    private Method userAccountingCb; //Armazena o metodo que deverá ser executado após o callback

    private NpSettings settings;
    private Pointer context;

    public NeuropilNode(int port, String host, String proto, String dnsName, boolean autoRun, String logWriteFn) {
        this.port = port;
        this.host = host;
        this.proto = proto;
        this.dnsName = dnsName;
        this.autoRun = autoRun;
        this.logWriteFn = logWriteFn;

        Neuropil neuropil = LoadLibrary.getInstance().neuropil;
        this.settings = neuropil.np_default_settings(null);

        this.context = neuropil.np_new_context(this.settings);

        final ObjectReferenceManager referenceManager = NeuropilObjectManager.getInstance().objectReferenceManager;
        this.userdata = referenceManager.add(this);
        neuropil.np_set_userdata(this.context, this.userdata);

        neuropil.np_listen(this.context, proto, host, port, dnsName);

        if(this.autoRun){
            run( 0);
        }
    }

    public NeuropilNode(int port, String host, String proto,  boolean autoRun, String logWriteFn) {
        this(port, host, proto, null, autoRun,logWriteFn);
    }

    public NeuropilNode(int port, boolean autoRun, String logWriteFn) {
         this(port, "localhost", "udp4", null, autoRun, logWriteFn);
    }

    public String getAddress(){
        try{
            Neuropil neuropil = LoadLibrary.getInstance().neuropil;
            byte[] address = new byte[500];
            for(int i=0; i < address.length; i++){
                address[i] = '\0';
            }
            int status = neuropil.np_get_address(this.context, address, 255);
            if(NpReturn.NP_OK.intValue() != status){
                throw new Exception(neuropil.np_error_str(status));
            }

            String utf8Address = new String(address, StandardCharsets.UTF_8).trim();

            return utf8Address;
        } catch (Exception e){
            e.printStackTrace();
        }
        return null;
    }

    public int join(String connectString){
        int ret = 0;
        try{
            Neuropil neuropil = LoadLibrary.getInstance().neuropil;

            ret = neuropil.np_join(this.context, connectString);
            if(NpReturn.NP_OK.intValue() != ret) {
                throw new Exception(neuropil.np_error_str(ret));
            }
            return ret;
        } catch (Exception e){
            e.printStackTrace();
        }
        return ret;
    }

    public int getStatus(){
        int ret = 0;
        try{
            Neuropil neuropil = LoadLibrary.getInstance().neuropil;
            ret = neuropil.np_get_status(this.context);
            return ret;
        } catch (Exception e){
            e.printStackTrace();
        }
        return ret;
    }

    public boolean hasJoined(){
        Neuropil neuropil = LoadLibrary.getInstance().neuropil;
        return neuropil.np_has_joined(this.context);
    }

    public int run(double duration){
        int ret = 0;
        try{
            Neuropil neuropil = LoadLibrary.getInstance().neuropil;
            ret = neuropil.np_run(this.context, duration);
            if(NpReturn.NP_OK.intValue() != ret) {
                throw new Exception(neuropil.np_error_str(ret));
            }
            return ret;
        } catch (Exception e){
            e.printStackTrace();
        }
        return ret;
    }


    public NpToken newIdentity(byte[] secretKey){
        try {
            Neuropil neuropil = LoadLibrary.getInstance().neuropil;
            Double expiresAt = (System.currentTimeMillis() / 1000.0) + (60 * 60 * 24);

            byte[] internalSecretKey = null;
            if(Objects.nonNull(secretKey)) {
                if (secretKey.length > NpLimits.NP_SECRET_KEY_BYTES.intValue()) {
                    throw new Exception("Parameter secretKey must have maximum" + NpLimits.NP_SECRET_KEY_BYTES.intValue() + " bytes");
                }
                internalSecretKey = Arrays.copyOf(secretKey, NpLimits.NP_SECRET_KEY_BYTES.intValue());
            }

            NpToken token = neuropil.np_new_identity_java(this.context, expiresAt, internalSecretKey);
            return token;
        } catch (Exception e){
            e.printStackTrace();
        }
        return null;
    }

    public NpToken newIdentity(){
        return newIdentity( null);
    }

    public int useIdentity(NpToken npToken){
        int ret = 0;
        try{
            Neuropil neuropil = LoadLibrary.getInstance().neuropil;
            ret = neuropil.np_use_identity_java(context, npToken);
            if(NpReturn.NP_OK.intValue() != ret) {
                throw new Exception(neuropil.np_error_str(ret));
            }
            return ret;
        } catch (Exception e){
            e.printStackTrace();
        }
        return ret;
    }

    public void shutdown(){
        this.destroyed = true;
        Neuropil neuropil = LoadLibrary.getInstance().neuropil;
        neuropil.np_destroy(this.context, true);

    }

    public void setAuthenticateCb(Method method){
        Neuropil neuropil = LoadLibrary.getInstance().neuropil;
        this.userAuthenticateCb = method;
        try{
            int ret = neuropil.np_set_authenticate_cb(this.context, new JavaAuthenticateCbImpl());
            if(NpReturn.NP_OK.intValue() != ret) {
                throw new Exception(neuropil.np_error_str(ret));
            }
        } catch (Exception e){
            e.printStackTrace();
        }
    }

    public void setAuthorizeCb(Method method){
        Neuropil neuropil = LoadLibrary.getInstance().neuropil;
        this.userAuthorizeCb = method;
        try{
            int ret = neuropil.np_set_authorize_cb(this.context, new JavaAuthorizeCbImpl());
            if(NpReturn.NP_OK.intValue() != ret) {
                throw new Exception(neuropil.np_error_str(ret));
            }
        } catch (Exception e){
            e.printStackTrace();
        }
    }

    public void setAccountingCb(Method method) {
        Neuropil neuropil = LoadLibrary.getInstance().neuropil;
        this.userAccountingCb = method;
        try {
            int ret = neuropil.np_set_accounting_cb(this.context, new JavaAccountingCbImpl());
            if (NpReturn.NP_OK.intValue() != ret) {
                throw new Exception(neuropil.np_error_str(ret));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public int getPort() {
        return port;
    }

    public void setPort(int port) {
        this.port = port;
    }

    public String getHost() {
        return host;
    }

    public void setHost(String host) {
        this.host = host;
    }

    public String getProto() {
        return proto;
    }

    public void setProto(String proto) {
        this.proto = proto;
    }

    public String getDnsName() {
        return dnsName;
    }

    public void setDnsName(String dnsName) {
        this.dnsName = dnsName;
    }

    public boolean isAutoRun() {
        return autoRun;
    }

    public void setAutoRun(boolean autoRun) {
        this.autoRun = autoRun;
    }

    public boolean isDestroyed() {
        return destroyed;
    }

    public void setDestroyed(boolean destroyed) {
        this.destroyed = destroyed;
    }

    public String getLogWriteFn() {
        return logWriteFn;
    }

    public void setLogWriteFn(String logWriteFn) {
        this.logWriteFn = logWriteFn;
    }

    public Pointer getUserdata() {
        return userdata;
    }

    public void setUserdata(Pointer userdata) {
        this.userdata = userdata;
    }

    public Method getUserAuthenticateCb() {
        return userAuthenticateCb;
    }

    public void setUserAuthenticateCb(Method userAuthenticateCb) {
        this.userAuthenticateCb = userAuthenticateCb;
    }

    public Method getUserAuthorizeCb() {
        return userAuthorizeCb;
    }

    public void setUserAuthorizeCb(Method userAuthorizeCb) {
        this.userAuthorizeCb = userAuthorizeCb;
    }

    public Method getUserAccountingCb() {
        return userAccountingCb;
    }

    public void setUserAccountingCb(Method userAccountingCb) {
        this.userAccountingCb = userAccountingCb;
    }

    public NpSettings getSettings() {
        return settings;
    }

    public void setSettings(NpSettings settings) {
        this.settings = settings;
    }

    public Pointer getContext() {
        return context;
    }

    public void setContext(Pointer context) {
        this.context = context;
    }

    @Override
    public String toString() {
        return "NeuropilNode{" +
                "port=" + port +
                ", host='" + host + '\'' +
                ", proto='" + proto + '\'' +
                ", dnsName='" + dnsName + '\'' +
                ", autoRun=" + autoRun +
                ", destroyed=" + destroyed +
                ", logWriteFn='" + logWriteFn + '\'' +
                ", userdata=" + userdata +
                ", userAuthenticateCb=" + userAuthenticateCb +
                ", userAuthorizeCb=" + userAuthorizeCb +
                ", userAccountingCb=" + userAccountingCb +
                ", settings=" + settings +
                ", context=" + context +
                '}';
    }
}
