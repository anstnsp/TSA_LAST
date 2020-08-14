package com.finger.tsa.signature;


import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.tsp.*;

import java.io.IOException;

import java.math.BigInteger;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TSAClient {
	
		private static final Logger logger = LoggerFactory.getLogger(TSAClient.class);

	    private final MessageDigest digest;
		private X509Certificate cert;
		private PrivateKey privateKey;

	    /**
	     * @param username user name of TSA - pass if the tsaURL need sign in
	     * @param password password of TSA - pass if the tsaURL need sign in
	     * @param digest   the message digest to use
	     */
	    TSAClient(MessageDigest digest, X509Certificate cert, PrivateKey privateKey) {
	        this.digest = digest;
	        this.cert = cert;
	        this.privateKey = privateKey;
	    }

	    /**
	     * @param messageImprint imprint of message contents
	     * @return the encoded time stamp token
	     * @throws IOException if there was an error with the connection or data from the TSA server,
	     *                     or if the time stamp response could not be validated
	     * @throws OperatorCreationException 
	     * @throws CertificateException 
	     */
	    byte[] getTimeStampToken(byte[] messageImprint) throws IOException, TSPException, CertificateException, OperatorCreationException, NoSuchAlgorithmException {
	        this.digest.reset();
	        
	        byte[] hash = this.digest.digest(messageImprint);

	        // generate cryptographic nonce
	        SecureRandom random = new SecureRandom();
	        int nonce = random.nextInt();

	        // generate TSA request
	        TimeStampRequestGenerator tsaGenerator = new TimeStampRequestGenerator();
	        tsaGenerator.setCertReq(true);
	        ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier(NISTObjectIdentifiers.id_sha256.getId());
	        TimeStampRequest request = tsaGenerator.generate(oid, hash, BigInteger.valueOf(nonce));
	       	//request.getEncoded() 이게 TimeStampReq 클래스임.. 
	        // get TSA response
	        byte[] tsaResponse = getTSAResponse(request.getEncoded());

	        TimeStampResponse response = new TimeStampResponse(tsaResponse);
	        response.validate(request);
	        
	        TimeStampToken token = response.getTimeStampToken();
	      
	        //타임스탬프토큰의 검증
	        SigUtils.validateTimestampToken(token, cert);
	   
	        if (token == null) {
	            throw new IOException("Response does not have a time stamp token");
	        }

	        return token.getEncoded();
	    }

	    private byte[] getTSAResponse(byte[] request) throws IllegalArgumentException, IOException, TSPException, CertificateEncodingException, OperatorCreationException {
	    	TimeStampRequest clientRequest = null;
	    	TimeStampTokenGenerator tstg = null;
	    	TimeStampToken token = null; 
	    	TimeStampResponse tsResp = null;
	    	TimeStampResponseGenerator tsRespGen = null;
	    	
	    	try {
	    		clientRequest = new TimeStampRequest(request);
	    		SignerInfoGenerator signerInfo = new JcaSimpleSignerInfoGeneratorBuilder().build("SHA256withRSA",privateKey, cert);
				DigestCalculator digestCal = new JcaDigestCalculatorProviderBuilder().build().get(new AlgorithmIdentifier(new ASN1ObjectIdentifier(NISTObjectIdentifiers.id_sha256.getId())));
				ASN1ObjectIdentifier tsaPolicy = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.1");
				tstg = new TimeStampTokenGenerator(signerInfo, digestCal, tsaPolicy);
				
				Date TokenGenTime = new Date(); //토큰생성시간
				token = tstg.generate(clientRequest, BigInteger.ONE, TokenGenTime);
				Set<String> set = new HashSet<String>();
				set.add(NISTObjectIdentifiers.id_sha256.getId());
				tsRespGen = new TimeStampResponseGenerator(tstg, set);
				tsResp = tsRespGen.generate(clientRequest, BigInteger.ONE, TokenGenTime);
				tsResp.validate(clientRequest); //응답검증. 
				
				if( tsResp.getStatus() != 0) {
					logger.error("TimeStampResponse Status:"+ tsResp.getStatus());
					logger.error("TimeStamperResponse StatusString: "+ tsResp.getStatusString());
					PKIFailureInfo failInfo = tsResp.getFailInfo();
					if( failInfo != null) logger.error("fail info int value :"+failInfo.intValue()); 
				}
				
				return tsResp.getEncoded(); 
	    	} catch(CertificateEncodingException e) {
	    		logger.error("error occur while encoding certificate. maybe you used malformed certificate, msg: {}", e.getMessage());
	    		throw e;
	    	} catch(OperatorCreationException e) {
	    		logger.error("error occur while create security builder msg: {}", e.getMessage());
	    		throw e;
	    	} catch(IOException e) {
	    		logger.error("TSAClient request is malformed, msg: {}", e.getMessage());
	    		throw e;
	    	} catch(IllegalArgumentException e) {
	    		logger.error("inappropriate argument in security builder, msg: {}", e.getMessage());
	    		throw e;
	    	} catch(TSPException e) {
	    		logger.error("TSP request or response fails to validate. msg: {}", e.getMessage());
	    		throw e;
	    	}
	    	
	    }
}
