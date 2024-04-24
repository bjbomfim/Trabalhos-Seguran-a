import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;

/*
 * MySignature
 * 
 * Integrantes:
 *  - Alexandre R. Bomfim Jr.
 *  - João Pedro Maia
 * 
 */

public class MySignatureTest {
    public static void main(String[] args) {
        try {
            System.out.println("\n\n----------------------Inicio-----------------------------\n");

            if(args.length < 2){
                throw new Exception("Argumentos nao passados.\n");
            }

            String algorithm = args[0];
            byte[] plainText = args[1].getBytes("UTF8");

            String algotype = "RSA";

            System.out.println( "Iniciando a geraçao da chave.\n" );
            KeyPairGenerator keyGen = null;
            
            if(algorithm.toUpperCase().equals("SHA256withECDSA".toUpperCase())){
                throw new Exception("Algoritmo SHA256withECDSA nao suportado. Por enquanto.");
            } 
            keyGen = KeyPairGenerator.getInstance(algotype);
            keyGen.initialize(2048);

            KeyPair key = keyGen.generateKeyPair();

            System.out.println( "Finalizado a geraçao da chave.\n\n" );
            MySignature sig = MySignature.getInstance(algorithm);
            
            System.out.println("---------------------------------------------------------\n");
            
            System.out.println("Iniciando a assinatura.\n");
            sig.initSign(key.getPrivate());
            sig.update(plainText);

            System.out.println("Completando a assinatura.\n");
            byte[] signature = sig.sign();
            System.out.println("Assinatura finalizada.\n\n");

            System.out.println("---------------------------------------------------------\n");

            System.out.println("Resumo de mensagem\n");
            System.out.println(sig.getDigest()+"\n");

            System.out.println("String em Hexadecimal.\n");
            StringBuffer buf = new StringBuffer();
            for(int i = 0; i < signature.length; i++) {
                String hex = Integer.toHexString(0x0100 + (signature[i] & 0x00FF)).substring(1);
                buf.append((hex.length() < 2 ? "0" : "") + hex);
            }
            System.out.println(buf.toString()+"\n\n");

            System.out.println("---------------------------------------------------------\n");
            
            System.out.println( "Inicio da verificacao de assinatura.\n" );
            sig.initVerify(key.getPublic());
            sig.update(plainText);
            if (sig.verify(signature)) {
                System.out.println( "Assinatura digital verificada. Deu green.\n" );
            } else System.out.println( "Assinatura digital falhou. Deu red.\n" );

            System.out.println("-------------------------Fim-----------------------------\n\n\n");
        } catch (Exception e) {
            System.err.println("Exception [Main]: "+e.getMessage());
        }
    }
}
