package com.finger.tsa.signature;


import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.tsp.TSPException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.security.*;

import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Arrays;


public class Signature implements SignatureInterface{
	private PrivateKey privateKey;
    private X509Certificate certificate;
    private static final Logger logger = LoggerFactory.getLogger(Signature.class);
    //애는 그냥 키두개, url 받으면댐... 
    Signature(PrivateKey privateKey, X509Certificate certificate) throws CertificateExpiredException, CertificateNotYetValidException {
        this.privateKey = privateKey;
        this.certificate = certificate;

        if (certificate instanceof X509Certificate) {
            ((X509Certificate) certificate).checkValidity();
        }
  
    }

    @Override
    public byte[] sign(InputStream content) throws IOException {
        try {
            CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
            X509Certificate cert = this.certificate;
            ContentSigner sha1Signer = new JcaContentSignerBuilder("SHA256WithRSA").build(this.privateKey);
            gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().build()).build(sha1Signer, cert));
            gen.addCertificates(new JcaCertStore(Arrays.asList(this.certificate)));
            CMSProcessableInputStream msg = new CMSProcessableInputStream(content);
            CMSSignedData signedData = gen.generate(msg, false);
            
            TimeStampManager timeStampManager = new TimeStampManager(this.certificate, this.privateKey);
            signedData = timeStampManager.addSignedTimeStamp(signedData);
        
            return signedData.getEncoded();
        } catch (GeneralSecurityException | CMSException | OperatorCreationException | TSPException e) {
            //throw new IOException cause a SignatureInterface, but keep the stacktrace
        	logger.error("error occur while >> byte[] sign(InputStream content) :"+e.getMessage());
            throw new IOException(e);
        } 
    }
}
