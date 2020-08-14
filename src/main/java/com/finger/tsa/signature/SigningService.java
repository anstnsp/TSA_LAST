package com.finger.tsa.signature;

import org.apache.commons.io.FileUtils;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.stereotype.Service;

import com.finger.tsa.common.advice.FchainException;
import com.finger.tsa.util.Util;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;

import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.Calendar;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


@Service
public class SigningService {
	 
		private static final Logger logger = LoggerFactory.getLogger(SigningService.class);

	    private final MessageSource messageSource;
	    @Value("${env.privKeyPath}")
	    private String PRIVKEY_PATH;
	    @Value("${env.pubKeyPath}")
	    private String PUBKEY_PATH;
	   
	    public SigningService(MessageSource messageSource) {
	        this.messageSource = messageSource;
	    }

	    public byte[] signPdf(byte[] pdfToSign) throws NoSuchAlgorithmException, InvalidKeySpecException, NullPointerException, FchainException {
	        try {
	        	String priKeyPath = Util.resourcesUrlPath(PRIVKEY_PATH);
	        	String pubKeyPath = Util.resourcesUrlPath(PUBKEY_PATH);
	        	
	        	PrivateKey privateKey = Util.getPrivateKey(priKeyPath);   //NoSuchAlgorithmException, InvalidKeySpecException, NullPointerException
	            X509Certificate certificate = Util.getPublicKey(pubKeyPath); // CertificateException, NullPointerException
	            
	            Signature signature = new Signature(privateKey, certificate);  
	            //Signature signature = new Signature(keyStore, this.keyStorePassword.toCharArray(), certificateAlias, tsaUrl);
	            //create temporary pdf file
	            File pdfFile = File.createTempFile("pdf", "");
	            //write bytes to created pdf file
	            FileUtils.writeByteArrayToFile(pdfFile, pdfToSign);

	            //create empty pdf file which will be signed
	            File signedPdf = File.createTempFile("signedPdf", "");
	         
	            //sign pdfFile and write bytes to signedPdf
	            this.signDetached(signature, pdfFile, signedPdf); // (서명, 서명할 파일, 서열된파일) 

	            byte[] signedPdfBytes = Files.readAllBytes(signedPdf.toPath());

	            //remove temporary files
	            pdfFile.deleteOnExit();
	            signedPdf.deleteOnExit();

	            return signedPdfBytes;   
	        } catch (CertificateExpiredException e) {
	        	logger.error("Certificate is expired", e);
		        throw new FchainException(Integer.valueOf(getMessage("expiredCert.code")), getMessage("expiredCert.msg"));
	        } catch (CertificateNotYetValidException e) {
	        	logger.error("Not yet valid Certificate", e);
		        throw new FchainException(Integer.valueOf(getMessage("invalidCert.code")), getMessage("invalidCert.msg"));	        	
	        } catch (CertificateException e) {
	            logger.error("Cannot obtain proper KeyStore or Certificate", e);
	            throw new FchainException(Integer.valueOf(getMessage("improperCert.code")), getMessage("improperCert.msg"));
	        } catch (IOException e) {
	        	logger.error("Cannot obtain proper file OR sign error", e);
	            throw new FchainException(Integer.valueOf(getMessage("noProperFile.code")), getMessage("noProperFile.msg"));
	        } 
	    }

	    private void signDetached(SignatureInterface signature, File inFile, File outFile) throws IOException {
	        if (inFile == null || !inFile.exists()) {
	        	logger.error("Document for signing does not exist");
	            throw new FileNotFoundException("Document for signing does not exist");
	        }
	        FileOutputStream fos = null;
	        PDDocument doc = null;
	        try {
	        	 fos = new FileOutputStream(outFile);
	        	 doc = PDDocument.load(inFile);
	             signDetached(signature, doc, fos);
	        } catch(IOException e) {
	        	logger.error("error occur while pdf signing");
	        	throw e; 
	        } finally {
	        	if(fos != null) try { fos.close();} catch(IOException e) { 
		    		logger.error("fos.close(), msg:"+e.getMessage()); 
		    		
		    	}
	        	if(doc != null) try { doc.close();} catch(IOException e) { 
		    		logger.error("doc.close(), msg:"+e.getMessage()); 
		    	
		    	}
	        }
	    }

	    private void signDetached(SignatureInterface signature, PDDocument document, OutputStream output) throws IOException {
	    	try {
		    	// create signature dictionary
		    	PDSignature pdSignature = new PDSignature();
		    	pdSignature.setType(COSName.DOC_TIME_STAMP);
		        pdSignature.setSubFilter(COSName.getPDFName("ETSI.RFC3161"));
		        pdSignature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
		        pdSignature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
		        pdSignature.setName("nonghyup");
		        pdSignature.setReason("This file is validated by nonghyup");
		      
		        // the signing date, needed for valid signature
		        pdSignature.setSignDate(Calendar.getInstance());

		        // register signature dictionary and sign interface
		        document.addSignature(pdSignature, signature);

		        // write incremental (only for signing purpose)
		        // use saveIncremental to add signature, using plain save method may break up a document
		        document.saveIncremental(output);	    		
		        document.close();
		        output.close();
	    	} catch(IOException e) {
	    		logger.error("signDetached IOException :error occur while pdf signing");
	    		throw e; 
	    	} finally {
	    		if(document != null) try { document.close();} catch(IOException e) { 
		    		logger.error("document.close(), msg:"+e.getMessage()); 
		    		
		    	}
	    		if(output != null)  try { output.close();} catch(IOException e) { 
		    		logger.error("output.close(), msg:"+e.getMessage()); 
		    		
		    	}
	    	}
	    }
	    
	    //code정보에 해당하는 메시지를 조회.
	    private String getMessage(String code) {
	        return getMessage(code, null);
	    }
	    //code정보, 추가 argument로 현재 locale에 맞는 메시지를 조회.
	    private String getMessage(String code, Object[] args) {
	        return messageSource.getMessage(code, args, LocaleContextHolder.getLocale());
	    }

}
