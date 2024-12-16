package bank.frmkSecurity;

import com.wm.data.*;
import com.wm.util.Values;
import com.wm.app.b2b.server.Service;
import com.wm.app.b2b.server.ServiceException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.util.Base64;

public final class jwt

{
	// ---( internal utility methods )---

	final static jwt _instance = new jwt();

	static jwt _newInstance() { return new jwt(); }

	static jwt _cast(Object o) { return (jwt)o; }

	// ---( server methods )---




	public static final void generateToken (IData pipeline)
        throws ServiceException
	{
		// --- <<IS-START(generateToken)>> ---
		// @sigtype java 3.5
		// [i] field:0:required header
		// [i] field:0:required payload
		// [i] object:0:required bPrivatKey
		// [o] field:0:required token
		// pipeline
		IDataCursor pipelineCursor = pipeline.getCursor();
		    String	payload = IDataUtil.getString( pipelineCursor, "payload" );
			String	header = IDataUtil.getString( pipelineCursor, "header" );
			byte[] bPrivatKey = (byte[]) IDataUtil.get( pipelineCursor, "bPrivatKey" );
			String  token= null;
		pipelineCursor.destroy();
		try {
			// encode header
			String headerEncoded = Base64.getUrlEncoder().withoutPadding().encodeToString(header.getBytes());
			
			//encode payload
			 String payloadEncoded = Base64.getUrlEncoder().withoutPadding().encodeToString(payload.getBytes());
			 
			 // concant header + paylod
			 String signatureCreatedFromThisData = headerEncoded + "." + payloadEncoded;
			 // get private key
			 PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(bPrivatKey);
			 KeyFactory kf = KeyFactory.getInstance("RSA");
			 PrivateKey privatKey = kf.generatePrivate(keySpec);
			 
			//Creating a Signature object
			
			Signature sign = Signature.getInstance("SHA256WithRSA");
			sign.initSign(privatKey);
			
			sign.update(signatureCreatedFromThisData.getBytes());
			
			String signeddata = Base64.getUrlEncoder().withoutPadding().encodeToString(sign.sign());
			
			token = signatureCreatedFromThisData + "." + signeddata;
		} catch (Exception e) {
			throw new ServiceException(e);
		}
		// pipeline
		IDataCursor pipelineCursor_1 = pipeline.getCursor();
		IDataUtil.put( pipelineCursor_1, "token", token);
		pipelineCursor_1.destroy();
			
		// --- <<IS-END>> ---

                
	}
}

