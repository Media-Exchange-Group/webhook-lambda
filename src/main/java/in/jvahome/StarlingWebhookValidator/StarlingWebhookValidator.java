package in.jvahome.StarlingWebhookValidator;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;

/**
 * Starling bank webhook validator lambda function
 *
 */
public class StarlingWebhookValidator implements RequestHandler <String[], String>
{

	@Override
	public String handleRequest(String[] input, Context context) {
		  if (input.length != 3) {
		      return "Expected 3 arguments but got " + input.length;
		    }

		    try {
				if (isValid(input[0], input[1], input[2])) {
				  return "Good webhook signature";
				} else {
				  return "Bad webhook signature";
				}
			} catch (InvalidKeyException e) {
				System.out.println("Invalid key");
				e.printStackTrace();
			} catch (NoSuchAlgorithmException e) {
				System.out.println("No such algorithm");
				e.printStackTrace();
			} catch (InvalidKeySpecException e) {
				System.out.println("Invalid key sec");
				e.printStackTrace();
			} catch (SignatureException e) {
				System.out.println("Invalid signature");
				e.printStackTrace();
			}
			return null;
	}
	
	  static boolean isValid(String publicKey, String signature, String jsonPayload)
		      throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException {
//			  System.out.println("Public key: "+publicKey);
//			  System.out.println("Signature: "+signature);
//			  System.out.println("Payload: "+jsonPayload);
			  System.out.println("Public key: "+publicKey.substring(0, 75)+"...");
			  System.out.println("Signature: "+signature.substring(0, 75)+"...");
			  System.out.println("Payload: "+jsonPayload);

		    X509EncodedKeySpec x509publicKey = new X509EncodedKeySpec(Base64.getDecoder().decode(publicKey));

		    Signature signAlg = Signature.getInstance("SHA512withRSA");
		    signAlg.initVerify(KeyFactory.getInstance("RSA").generatePublic(x509publicKey));
		    signAlg.update(jsonPayload.getBytes());

			boolean validationResult = signAlg.verify(Base64.getDecoder().decode(signature));

			if (validationResult) {
				System.out.println("Good webhook signature");
			} else {
				System.out.println("Bad webhook signature");
			}

		    return validationResult;
		  }	
	
}
