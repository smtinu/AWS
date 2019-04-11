package gtc.client;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.net.URL;
import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.SimpleTimeZone;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.HttpsURLConnection;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import com.github.seanroy.aws_signer.SigningTask;

public class Main {
	
	
    public static String toHex(byte [] bytes) {
        try {
        	
            return String.format("%040x", new BigInteger(1, bytes));
        } catch (Exception e) {
            e.printStackTrace();
        }

        return new String(bytes);
    }
    
    public static byte [] hash(String payload) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(payload.getBytes("UTF-8"));
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        return payload.getBytes();
    }
    
    public static String bytesToHex(byte[] hash) {
        StringBuffer hexString = new StringBuffer();
        for (int i = 0; i < hash.length; i++) {
        String hex = Integer.toHexString(0xff & hash[i]);
        if(hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }
        return hexString.toString();
    }
	

    
	static byte[] HmacSHA256(String data, byte[] key) throws Exception {
	    String algorithm="HmacSHA256";
	    Mac mac = Mac.getInstance(algorithm);
	    mac.init(new SecretKeySpec(key, algorithm));
	    return mac.doFinal(data.getBytes("UTF-8"));
	}

	static byte[] getSignatureKey(String key, String dateStamp, String regionName, String serviceName) throws Exception {
	    byte[] kSecret = ("AWS4" + key).getBytes("UTF-8");
	    byte[] kDate = HmacSHA256(dateStamp, kSecret);
	    byte[] kRegion = HmacSHA256(regionName, kDate);
	    byte[] kService = HmacSHA256(serviceName, kRegion);
	    byte[] kSigning = HmacSHA256("aws4_request", kService);
	    return kSigning;
	    
	}	
	
	public static void main(String[] args) throws Throwable {
        //String method = "GET";
		String method = "POST";
		Date currentdate = new Date();
        String timeStamp = SigningTask.dateFormat.format(currentdate);


        String accessKey = "AKIAI4K6H644IB7A4TWQ";
        String accessSecret = "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";
        //String canonicalURI = "/services/sfs/v1/ownerships/1003234576898765/telematics/remote-lock/async-request";
        //String canonicalURI = "/services/sfs/v1/ownerships/1003234576898765/telematics/remote-lock/results/100100000000008213";
        //String canonicalURI = "/services/sfs/v1/ownerships/1003234576898765/telematics/car-finder-horn-light/async-request";
        //String canonicalURI = "/services/sfs/v1/ownerships/1003234576898765/telematics/remote-engine/async-request";
        //String canonicalURI = "/services/sfs/v1/ownerships/1003234576898765/telematics/remote-tailgate-lock/async-request";
        //String canonicalURI = "/services/sfs/v1/ownerships/1003234576898765/telematics/dashboard/latest";
        String canonicalURI = "/services/sfs/v1/ownerships/1003264222333230/telematics/poi/async-request";
        
        
        String xAPIKey="YUYCjDeVDs8wrEUTIAg6R8VWg14wOi8j4KgIg7FL";
        String externalSystemID="HMETSP";
        String region = "eu-west-1";
        String service = "execute-api";
        /////////////////////////////////////////////
        //String eventtime="2008-11-07T09:00:00+00:00";
        DateFormat eventtimeformat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssXXX");
        eventtimeformat.setTimeZone(new SimpleTimeZone(SimpleTimeZone.UTC_TIME, "UTIC"));
        String eventtime= eventtimeformat.format(currentdate);
        /////////////////////////////////////////////
        String vin="93210000000000005";
        String onetimeuuid="fb5a68d8-88db-4065-9ae7-3f2cedd633b0";
     
		//conn.setRequestProperty("X-Gtc-External-System-Id",VDHConstants.GTC_EXTERNAL_SYSTEM_ID);
		//conn.setRequestProperty("productOwnId", param.getxProductOwnId());
                
        String cannonicalHeader = "content-type:" +"application/json; charset=utf-8"+ '\n' +
        						"host:" + "pri-q1-eu.gtc20.com" + '\n' + 
        						"x-amz-date:" + timeStamp + '\n' + 
        						"x-api-key:" + xAPIKey + '\n' + 
        						"x-event-time:" + eventtime + '\n' + 
        						//"x-gtc-external-system-id:" + externalSystemID +'\n' +
        						"x-one-time-uuid:" + onetimeuuid + '\n' + 
        						"x-vin:" + vin + '\n';
        //String signedHeader = "content-type;host;x-amz-date;x-api-key;x-event-time;x-gtc-external-system-id;x-one-time-uuid;x-vin";
        String signedHeader = "content-type;host;x-amz-date;x-api-key;x-event-time;x-one-time-uuid;x-vin";
     
        //String payloadHash = DigestUtils.sha256Hex("{\"command\" : \"allLock\"}");
        //String payloadHash = DigestUtils.sha256Hex("{\"command\" : \"allLock\"}");
        //String payloadHash = DigestUtils.sha256Hex("{\"command\" : \"horn-lights\"}");
       // String bodyParam="{\"name\": \"Carl-Legien-Straße 30, 63073 Offenbach am Main, Germany\",\"address\": {\"city\": \"Offenbach am Main\",\"state\": \"  \",\"zipCode\": \"63073\"},\"coordinates\": {\"latitude\": 180305453,\"longitude\": 31822055,\"datum\":\"wgs84\",\"format\": \"mas\"},\"poiProvider\": \"Google\"}";
        String bodyParam="{\"name\":\"ß\"}";
        
        System.out.println(bodyParam);
        
        String payloadHash = DigestUtils.sha256Hex(bodyParam.getBytes("UTF-8"));
        //String payloadHash = bytesToHex(hash(bodyParam));
        /*
        String payloadHash = DigestUtils.sha256Hex("{" + 
        	"\"vehicleControl\": {    \"acSetting\": {" +
        	      "\"acTempVal\": \"03\", " +
        	      "\"acDefSetting\": \"autoOn\" "+
        	    "}," +
        	    "\"vehicleStartTimer\": {" +
        	    "\"unit\": \"min\"," +
        	    "\"value\": 2" +
        	    "},"+
        	    "\"acTemporarySetting\": {" +
        	    "\"acDefSetting\": \"manualOn\""+
        	    "}" +
        	  "}," +
        	  "\"command\": \"start\""+
        	"}");*/
        //String canonicalRequest = method + '\n' + canonicalURI + '\n' + "languageCode=en" + '\n' + cannonicalHeader + '\n' + signedHeader + '\n' + payloadHash;
        String canonicalRequest = method + '\n' + canonicalURI + '\n'  + "" + '\n' + cannonicalHeader + '\n' + signedHeader + '\n' + payloadHash;
        String algorithm = "AWS4-HMAC-SHA256";
        String credentialScope =  timeStamp.substring(0,8)  + '/' + region+ '/' + service + '/' + "aws4_request";
        String stringToSign = "AWS4-HMAC-SHA256" + '\n' +  timeStamp + '\n' +  credentialScope + '\n' +   DigestUtils.sha256Hex(canonicalRequest);
        byte[] signingKey = (getSignatureKey(accessSecret, timeStamp.substring(0, 8), region, service));
        String signature = toHex(HmacSHA256(stringToSign, signingKey));
        String authHeader= algorithm + ' ' + "Credential=" + accessKey + '/' + credentialScope + ", " +  "SignedHeaders=" + signedHeader + ", " + "Signature=" + signature;

        System.out.println("************************* Canonical Request ***********************");
    	System.out.println(canonicalRequest);
    	System.out.println("*******************************************************************");

    	System.out.println("************************* String to Sign **************************");
    	System.out.println(stringToSign);
    	System.out.println("*******************************************************************");    	

    	System.out.println(authHeader);


		CloseableHttpClient httpclient = HttpClients.createDefault();
		//HttpPost httpPost = new HttpPost("https://pri-q1-eu.gtc20.com/services/sfs/v1/ownerships/1003234576898765/telematics/remote-lock/async-request");
		//HttpGet httpPost = new HttpGet("https://pri-q1-eu.gtc20.com/services/sfs/v1/ownerships/1003234576898765/telematics/remote-lock/results/100100000000008213");
		//HttpPost httpPost = new HttpPost("https://pri-q1-eu.gtc20.com/services/sfs/v1/ownerships/1003234576898765/telematics/car-finder-horn-light/async-request");
		//HttpPost httpPost = new HttpPost("https://pri-q1-eu.gtc20.com/services/sfs/v1/ownerships/1003234576898765/telematics/remote-engine/async-request");
		//HttpPost httpPost = new HttpPost("https://pri-q1-eu.gtc20.com/services/sfs/v1/ownerships/1003234576898765/telematics/remote-tailgate-lock/async-request");
		//HttpGet httpPost = new HttpGet("https://pri-q1-eu.gtc20.com/services/sfs/v1/ownerships/1003234576898765/telematics/dashboard/latest?languageCode=en");
		HttpPost httpPost = new HttpPost("https://pri-q1-eu.gtc20.com/services/sfs/v1/ownerships/1003264222333230/telematics/poi/async-request");
		
	    httpPost.addHeader("Content-Type", "application/json; charset=utf-8");
	    httpPost.addHeader("host", "pri-q1-eu.gtc20.com");
	    httpPost.addHeader("x-amz-Date", timeStamp);		
	    httpPost.addHeader("Authorization", authHeader);
		System.out.println(timeStamp);
		httpPost.addHeader("x-api-key", xAPIKey);
		//httpPost.addHeader("x-event-time", "2008-11-07T09:00:00+00:00");
		httpPost.addHeader("x-event-time", eventtime);
		httpPost.addHeader("x-vin", "93210000000000005");
		httpPost.addHeader("x-one-time-uuid", "fb5a68d8-88db-4065-9ae7-3f2cedd633b0");
		//httpPost.addHeader("x-gtc-external-system-id", "HMETSP");
		//httpPost.setEntity(new StringEntity("{\"command\" : \"allLock\"}"));
		//httpPost.setEntity(new StringEntity("{\"command\" : \"allLock\"}"));
	//	httpPost.setEntity(new StringEntity("{\"command\" : \"horn-lights\"}"));
		/*httpPost.setEntity(new StringEntity("{" + 
	        	"\"vehicleControl\": {    \"acSetting\": {" +
      	      "\"acTempVal\": \"03\", " +
      	      "\"acDefSetting\": \"autoOn\" "+
      	    "}," +
      	    "\"vehicleStartTimer\": {" +
      	    "\"unit\": \"min\"," +
      	    "\"value\": 2" +
      	    "},"+
      	    "\"acTemporarySetting\": {" +
      	    "\"acDefSetting\": \"manualOn\""+
      	    "}" +
      	  "}," +
      	  "\"command\": \"start\""+
      	"}"));*/
		
		//httpPost.setEntity(new StringEntity("{\"name\": \"Carl-Legien-Straße 30, 63073 Offenbach am Main, Germany\",\"address\": {\"city\": \"Offenbach am Main\",\"state\": \"  \",\"zipCode\": \"63073\"},\"coordinates\": {\"latitude\": 180305453,\"longitude\": 31822055,\"datum\":\"wgs84\",\"format\": \"mas\"},\"poiProvider\": \"Google\"}"));
		
		httpPost.setEntity(new StringEntity("{\"name\":\"ß\"}"));
		
		CloseableHttpResponse response1 = httpclient.execute(httpPost);

		try {
		    System.out.println(response1.getStatusLine());
		    
		    HttpEntity entity1 = response1.getEntity();
		    //  EntityUtils.consume(entity1);
		    System.out.println(convert(entity1.getContent(), Charset.defaultCharset()));
		    
		    for (int loop = 0; loop < response1.getAllHeaders().length; loop++) {
		        Header header = response1.getAllHeaders()[loop];
		        System.out.println(header.getName() + ":" + header.getValue() );
		    }

		    
		} finally {
		    response1.close();
		}
    	
    	
    	/*
    	try{
    	URL url = new URL(
				"https://pri-q1-eu.gtc20.com/services/sfs/v1/ownerships/123/telematics/remote-lock/results/123");
    	HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
		conn.setRequestMethod("POST");			
		conn.setRequestProperty("Content-Type", "application/json");			
		conn.setRequestProperty("host", "pri-q1-eu.gtc20.com");
		conn.setRequestProperty("x-amz-Date", timeStamp);		
		conn.setRequestProperty("Authorization", authHeader);
		System.out.println(timeStamp);
		conn.setRequestProperty("x-api-key", xAPIKey);
		conn.setRequestProperty("x-event-time", eventtime);
		conn.setRequestProperty("x-vin", "1997");
		conn.setRequestProperty("x-one-time-uuid", "fb5a68d8-88db-4065-9ae7-3f2cedd633b0");
		conn.setRequestProperty("x-gtc-external-system-id", "HMETSP");
		
		
		
		System.out.println("Resp Code:" + conn.getResponseCode());
		
    	}catch(Exception e){
    		e.printStackTrace();
    	}*/
		
		
	}


	public static  String convert(InputStream inputStream, Charset charset) throws IOException {

		StringBuilder stringBuilder = new StringBuilder();
		String line = null;

		try (BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(inputStream, charset))) {	
			while ((line = bufferedReader.readLine()) != null) {
				stringBuilder.append(line);
			}
		}

		return stringBuilder.toString();
	}
}