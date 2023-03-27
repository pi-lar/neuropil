package models;

import common.LoadLibrary;
import common.NeuropilObjectManager;
import enums.NpLimits;
import enums.NpReturn;
import interfaces.Neuropil;
import jnr.ffi.ObjectReferenceManager;
import jnr.ffi.Runtime;
import jnr.ffi.Struct;
import utils.NeuropilUtils;

public class NpToken extends Struct {

    public Struct.String uuid = new Struct.AsciiString(NpLimits.NP_UUID_BYTES.intValue());
    public Struct.String subject = new Struct.AsciiString(255);
    public Struct.String issuer = new Struct.AsciiString(NpLimits.NP_FINGERPRINT_BYTES.intValue());
    public Struct.String realm = new Struct.AsciiString(NpLimits.NP_FINGERPRINT_BYTES.intValue());
    public Struct.String audience = new Struct.AsciiString(NpLimits.NP_FINGERPRINT_BYTES.intValue());
    public Struct.Double issuedAt = new Double();
    public Struct.Double notBefore = new Double();
    public Struct.Double expiresAt = new Double();
    public Struct.String publicKey = new Struct.AsciiString(NpLimits.NP_PUBLIC_KEY_BYTES.intValue());
    public Struct.String secretKey = new Struct.AsciiString(NpLimits.NP_SECRET_KEY_BYTES.intValue());
    public Struct.String signature = new Struct.AsciiString(NpLimits.NP_SIGNATURE_BYTES.intValue());
    public Struct.String attributes = new Struct.AsciiString(NpLimits.NP_EXTENSION_BYTES.intValue());
    public Struct.String attributesSignature = new Struct.AsciiString(NpLimits.NP_SIGNATURE_BYTES.intValue());

    public NpToken(Runtime runtime) {
        super(runtime);
    }

    public void NpToken(String uuid, String subject,  String issuer, String realm, String audience, Double issuedAt,
                        Double notBefore, Double expiresAt, String publicKey, String secretKey, String signature,
                        String atributes, String atributesSignature){

        this.uuid = uuid;
        this.subject = subject;
        this.issuer = issuer;
        this.realm = realm;
        this.audience = audience;
        this.issuedAt = issuedAt;
        this.notBefore = notBefore;
        this.expiresAt = expiresAt;
        this.publicKey = publicKey;
        this.secretKey = secretKey;
        this.signature = signature;
        this.attributes = atributes;
        this.attributesSignature = atributesSignature;

    }

    public int getFingerprint(NeuropilNode node, boolean checkAttributes){
        int ret = 0;
        Neuropil neuropil = LoadLibrary.getInstance().neuropil;

        byte[] param = new byte[32];
        for(int i = 0; i < param.length; i++){
            param[i] = '\0';
        }

        NpId id = new NpId(param);
        //final ObjectReferenceManager referenceManager = NeuropilObjectManager.getInstance().objectReferenceManager;
        //jnr.ffi.Pointer npId = referenceManager.add(id);
        try{
            ret = neuropil.np_token_fingerprint_java(node.getContext(), this, checkAttributes, param);
            if(NpReturn.NP_OK.intValue() != ret) {
                throw new Exception(neuropil.np_error_str(ret));
            }
            return ret;
        } catch (Exception e){
            e.printStackTrace();
        }
        return ret;
    }

    public int getFingerprint(NeuropilNode node){
        return getFingerprint(node, false);

    }

}
