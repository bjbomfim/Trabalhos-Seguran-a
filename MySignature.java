import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.*;

/*
 * MySignature
 * 
 * Integrantes:
 *  - Alexandre R. Bomfim Jr.
 *  - João Pedro Maia
 * 
 */

public class MySignature {

    public enum MySignatureType {
        MD5withRSA, SHA1withRSA, SHA256withRSA, SHA512withRSA, SHA256withECDSA
    }

    public enum MySignatureState {
        SIGN, STANDBY, VERIFY
    }

    private MySignatureType signatureType;
    private PrivateKey privateKey;
    private PublicKey publicKey;
    private MySignatureState state;
    private MessageDigest digest;

    public static MySignature getInstance(String algorithmSignature) {
        try {
            MySignature mySignature = new MySignature();
            for (MySignatureType type : MySignatureType.values()) {
                if (type.name().toUpperCase().equals(algorithmSignature.toUpperCase())) {
                    mySignature.signatureType = type;
                    mySignature.state = MySignatureState.STANDBY;
                    break;
                }
            }
            if(mySignature.signatureType == null){
                throw new NoSuchAlgorithmException("Tipo de algoritmo invalido "+algorithmSignature+"\n");
            }
            return mySignature;
        } catch (Exception e) {
            System.err.println("Exception [getInstance]: "+e.getMessage()+"\n");
            return null;
        }
    }

    public void initSign(PrivateKey privateKey) {
        try {
            if(privateKey == null){
                throw new IllegalArgumentException("Erro: Chave privada não fornecida.\n");
            }
            this.privateKey = privateKey;
            this.state = MySignatureState.SIGN;
            if(privateKeyVerify()){

                this.digest = getMessageDigest();

                System.out.println("Chave recebida com sucesso, algoritmo escolhido: "+this.signatureType.name()+"\n");
            } else {
                throw new IllegalArgumentException("Erro: Algoritmo passado não suportada.\n");
            }
        } catch (Exception e) {
            this.privateKey = null;
            this.state = MySignatureState.STANDBY;
            System.err.println("Exception [initSign]: "+e.getMessage()+"\n");
        }
    }

    public void update(byte[] data) {
        try {
            if(this.state == MySignatureState.SIGN || this.state == MySignatureState.VERIFY){
                this.digest.update(data);
            } else {
                throw new Exception("Erro: Update nao esta pronto para ser utilizado.\n");
            }
        } catch (Exception e) {
            System.err.println("Exception [update]: "+e.getMessage());
        }
    }

    public byte[] sign() {
        try {
            if(this.state == MySignatureState.SIGN){
                byte[] data = this.digest.digest();
                return encryptWithPrivateKey(data, this.privateKey.getAlgorithm());
            } else {
                throw new Exception("Erro: Sign nao esta pronto para ser utilizado.\n");
            }
        } catch (Exception e) {
            System.err.println("Exception [sign]: "+e.getMessage()+"\n");
            return null;
        }
    }

    public void initVerify(PublicKey publicKey){
        try {
            if(publicKey == null){
                throw new Exception("Erro: Chave publica nao fornecida.\n");
            }
            this.publicKey = publicKey;
            this.state = MySignatureState.VERIFY;
            if(this.digest == null){
                this.digest = getMessageDigest();
            }

        } catch (Exception e) {
            System.err.println("Exception [initVerify]: "+e.getMessage());
        }
    }

    public boolean verify(byte[] signature){
        try {
            if(state == MySignatureState.VERIFY){
                byte[] data = this.digest.digest();

                byte[] decryptedSignature = decryptWithPublicKey(signature, this.privateKey.getAlgorithm());
                return MessageDigest.isEqual(data, decryptedSignature);
            } else {
                throw new Exception("Erro: verify nao esta pronto para uso.\n");
            }
        } catch (Exception e) {
            System.err.println("Exception [verify]: "+e.getMessage()+"\n");
            return false;
        }
    }

    public byte[] getDigest(){
        try {
            if(this.state == MySignatureState.SIGN){
                byte[] data = this.digest.digest();
                return data;
            } else {
                throw new Exception("Erro: Sign nao esta pronto para ser utilizado.\n");
            }
        } catch (Exception e) {
            System.err.println("Exception [getDigest]: "+e.getMessage()+"\n");
            return null;
        }
    }

    private boolean privateKeyVerify() {
        boolean flag = false;
        if(this.signatureType == MySignatureType.SHA256withECDSA){
            if(this.privateKey.getAlgorithm().equals("EC")){
                flag = true;
            }
        } else {
            if(this.privateKey.getAlgorithm().equals("RSA")){
                flag = true;
            }
        }
        return flag;
    }

    private MessageDigest getMessageDigest() throws NoSuchAlgorithmException {

        String algorithm = "SHA-256";

        switch (this.signatureType) {
            case MD5withRSA:
                algorithm = "MD5";
                break;
            case SHA1withRSA:
                algorithm = "SHA-1";
                break;
            case SHA512withRSA:
                algorithm = "SHA-512";
                break;
            default:
                break;
        }
        MessageDigest digest = MessageDigest.getInstance(algorithm);
        return digest;
    }

    private byte[] encryptWithPrivateKey(byte[] data, String algorithm) throws Exception {
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, this.privateKey);
        return cipher.doFinal(data);
    }

    private byte[] decryptWithPublicKey(byte[] signature,  String algorithm) throws Exception {
        Cipher cipher = Cipher.getInstance(algorithm); 
        cipher.init(Cipher.DECRYPT_MODE, this.publicKey);
        return cipher.doFinal(signature); 
    }

}