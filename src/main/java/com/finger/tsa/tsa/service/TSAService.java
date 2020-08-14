package com.finger.tsa.tsa.service;


import java.io.ByteArrayInputStream;

import java.io.IOException;

import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;

import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import java.text.SimpleDateFormat;
import java.util.Collection;
import java.util.List;

import java.util.concurrent.TimeoutException;

import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.cos.COSString;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.tsp.TimeStampTokenInfo;
import org.hyperledger.fabric.gateway.ContractException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.MessageSource;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.stereotype.Service;


import com.finger.tsa.FabricSDK;
import com.finger.tsa.common.advice.FchainException;
import com.finger.tsa.dto.RequestDto;
import com.finger.tsa.dto.ResponseDto;
import com.finger.tsa.signature.SigUtils;
import com.finger.tsa.signature.SigningService;
import com.finger.tsa.util.Util;

import lombok.RequiredArgsConstructor;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;


@Service
@RequiredArgsConstructor
@Configuration
public class TSAService {
	
	private final FabricSDK fabricSDK;
	private final MessageSource messageSource; 
	private final SigningService signingService;
	
	private static final Logger logger = LoggerFactory.getLogger(TSAService.class);
	
	@SuppressWarnings({ "unchecked", "static-access" })
	public String getFileIncludedToken(RequestDto dto) throws IllegalArgumentException, OperatorCreationException, TSPException, IOException, NullPointerException, TimeoutException, InterruptedException, FchainException, CMSException, GeneralSecurityException {
    	PDDocument doc = new PDDocument();
    	TimeStampToken timeStampToken = null;
    	ByteArrayInputStream certStream = null;
		try {
			//1.바이트배열로바꿈.
    	    byte[] buff = dto.getStrFromFile().getBytes();  
    	    //2.스트링으로 바꿈.
    	    String toStr = new String(buff);
    	    //base64디코딩. 
    	    byte[] b64dec = Util.base64Dec(toStr);
    	    
			//토큰이삽입된 파일(바이트배열) 얻어옴.
			byte[] signedPDF = signingService.signPdf(b64dec);
			
	    	//4.각파일을 해쉬함.(블록체인에 저장할 데이터)
			String PDFHashed = Util.getHashFromByteArray(b64dec); //원본문서해쉬 
			String signedPDFHshed = Util.getHashFromByteArray(signedPDF); //토큰삽입된 문서 해쉬 
			List<PDSignature> PDSList = doc.load(signedPDF).getSignatureDictionaries(); 
	    	//5.토큰이 삽입된 PDF 에서 토큰 추출    	
    		for(PDSignature sig : PDSList) {
    		   COSDictionary sigDict = sig.getCOSObject();
               COSString contents = (COSString) sigDict.getDictionaryObject(COSName.CONTENTS);
               
               byte[] byteArray = sig.getSignedContent(signedPDF);
               CMSProcessable signedContent = new CMSProcessableByteArray(byteArray);
               
               byte[] certData = contents.getBytes();
               CertificateFactory factory = CertificateFactory.getInstance("X.509");
               certStream = new ByteArrayInputStream(certData);
  		       CMSSignedData signedData = new CMSSignedData(signedContent, contents.getBytes());
  		       Collection<? extends Certificate> certs = factory.generateCertificates(certStream);
  		    
  		       X509Certificate cert = null;
	           for( Certificate tempCert : certs) {
	        	   if(SigUtils.checkTimeStampCertificateUsage((X509Certificate)tempCert) == false) {
	        		   logger.error("Certificate extended key usage does not include timeStamping");
	        		   throw new Error("Certificate extended key usage does not include timeStamping");
	        	   }
	        	   cert = (X509Certificate) tempCert;
	           }
	  		   Collection<SignerInformation> signers = signedData.getSignerInfos().getSigners();
		        if (signers.isEmpty())
		        {
		        	logger.error("No signers in signature");
		            throw new IOException("No signers in signature");
		        }
		        SignerInformation signerInformation = signers.iterator().next();
		        timeStampToken = SigUtils.extractTimeStampTokenFromSignerInformation(signerInformation); //토큰추출.
		        
		        //타임스탬프토큰의 유효성 체크
		        if(timeStampToken != null)  SigUtils.validateTimestampToken(timeStampToken, cert);
    		}
    		
    		TimeStampTokenInfo TSTInfo = timeStampToken.getTimeStampInfo();
			SimpleDateFormat dateFormat = new SimpleDateFormat("yyyyMMddHHmmss");
			String timeGenToken = dateFormat.format(TSTInfo.getGenTime());
    		
    		//타임스탬프토큰 base64인코딩 
    		String tokenEncodedString = Util.encodeBase64String(timeStampToken.getEncoded());
			//5.블록체인에 저장. (PdfHash: 원본pdf해쉬, PdfTokenHash: 토큰삽입된pdf해쉬, Tst: 타임스탬프토큰, IssuerDate: 토큰만들때 시점(yyyymmddhhmmss) , DocuSeq : 문서일련번호)
			
			//5-1.블록체인에 보낼 데이터 생성 
			JSONObject obj = new JSONObject();
			JSONObject obj2 = new JSONObject(); 

			obj.put("PdfTokenHash", signedPDFHshed);
			obj2.put("PdfHash", PDFHashed);
			//TODO.. 문서번호 요구사항에 맞게 바꿔야함. 
			obj2.put("DocuSeq", "3");
			obj2.put("Tst", tokenEncodedString);
			obj2.put("IssuerDate", timeGenToken); //보낼데이터(obj) 생성 끝 
			obj.put("TsaData", obj2);

			//2.블록체인에 위의 데이터를 저장. 
			fabricSDK.invokeTrasaction(obj);
			doc.close();
			certStream.close();
			//리턴은  토큰삽입된파일의 바이너리스트링값. 
			return new String(Util.base64Enc(signedPDF));
		
		} catch (ParseException e) {  
			logger.error("블록체인으로부터 받은 데이터포맷이 JSON형식이 아닙니다.");
			throw new FchainException(Integer.valueOf(getMessage("unKnown.code")), getMessage("unKnown.msg"));
		} catch (ContractException e) {
			JSONParser jsonParse = new JSONParser();
			JSONObject resultObj;
			try {
				resultObj = (JSONObject) jsonParse.parse(e.getMessage());
			} catch (ParseException e1) {
				logger.error("블록체인으로부터 받은 데이터포맷이 JSON형식이 아닙니다.");
				throw new FchainException(Integer.valueOf(getMessage("unKnown.code")), getMessage("unKnown.msg"));
			}
			logger.error("ContractException :"+e.getMessage());
			int code =  Integer.valueOf((String)resultObj.get("resultCode"));
			String msg = (String) resultObj.get("resultMessage");
			throw new FchainException(code, msg);
		} finally {
			if( doc != null) try { doc.close();} catch(IOException e) { 
	    		logger.error("doc.close(), msg:"+e.getMessage()); 
	    		
	    	}  
			if( certStream != null) try { certStream.close();} catch(IOException e) { 
	    		logger.error("certStream.close(), msg:"+e.getMessage()); 
	    		
	    	}
		}
	
	}
	
	public ResponseDto verifyPdfFile(RequestDto dto) throws NoSuchAlgorithmException, IOException, FchainException, ParseException {
		try {

			//1.받은 전자문서값 바이트배열로바꿈.
    	    byte[] buff = dto.getStrFromFile().getBytes();  
    	    //2.스트링으로 바꿈.
    	    String toStr = new String(buff);
    	    //base64디코딩. 
    	    byte[] b64dec = Util.base64Dec(toStr);
    		String signedPDFHshed = Util.getHashFromByteArray(b64dec); //토큰삽입된문서해쉬 

			//2.블록체인 내에 존재유무 확인 
			String result = fabricSDK.evaluateTransctionByHash(signedPDFHshed);

			//3.블록체인에서 조회한 데이터 파싱. 
			JSONParser jsonParse = new JSONParser();
			JSONObject resultObj = (JSONObject) jsonParse.parse(result);
			String pdfTokenHash = (String) resultObj.get("pdfTokenHash");
			String resultMessage = (String) resultObj.get("resultMessage");
			JSONObject resultMessageObj = (JSONObject)jsonParse.parse(resultMessage);
			
			String docuSeq = (String)resultMessageObj.get("docuSeq");
			String issuerDate = (String)resultMessageObj.get("issuerDate");
			String pdfHash = (String)resultMessageObj.get("pdfHash");
			String tst = (String)resultMessageObj.get("tst");
			
			//4.최종적으로 리턴할 데이터 responseDto 생성. 
			ResponseDto responseDto = ResponseDto.builder()
					  		   .pdfTokenHash(pdfTokenHash)
							   .pdfHash(pdfHash)
							   .docuSeq(docuSeq)
							   .issuerDate(issuerDate)
							   .tst(tst)
							   .build();
			return responseDto;	    
		
		} catch (ParseException e) {
			logger.error("ParseException : 블록체인으로부터 받은 데이터포맷이 JSON형식이 아닙니다.");
			throw new FchainException(Integer.valueOf(getMessage("unKnown.code")), getMessage("unKnown.msg"));
		} catch (ContractException e) {
			JSONParser jsonParse = new JSONParser();
			JSONObject resultObj = (JSONObject) jsonParse.parse(e.getMessage());
			logger.error("ContractException :"+e.getMessage());
			int code =  Integer.valueOf((String)resultObj.get("resultCode"));
			String msg = (String) resultObj.get("resultMessage");
			throw new FchainException(code, msg);
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
