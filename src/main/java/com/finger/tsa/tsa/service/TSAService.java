package com.finger.tsa.tsa.service;


import java.io.IOException;
import java.security.NoSuchAlgorithmException;

import java.text.SimpleDateFormat;


import java.util.concurrent.TimeoutException;


import org.bouncycastle.cms.CMSException;

import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.tsp.TimeStampTokenInfo;
import org.hyperledger.fabric.gateway.ContractException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.stereotype.Service;
import com.finger.tsa.FabricSDK;
import com.finger.tsa.common.advice.FchainException;

import com.finger.tsa.tsa.dto.TSADto;
import com.finger.tsa.util.Util;

import lombok.RequiredArgsConstructor;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;


@Service
@RequiredArgsConstructor
public class TSAService {
	
	private final FabricSDK fabricSDK;
	private final MessageSource messageSource; 

	private static final Logger logger = LoggerFactory.getLogger(TSAService.class);
	
	public TSADto verifyPdfFile(TSADto dto) throws FchainException, ParseException, IOException {
		try {
			//2.블록체인 내에 존재유무 확인 
			String result = fabricSDK.evaluateTransctionByHash(dto.getPdfTokenHash());

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
			TSADto responseDto = TSADto.builder()
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

	@SuppressWarnings("unchecked")
	public void insertBLC(TSADto dto) throws TimeoutException, InterruptedException, ParseException, IOException, CMSException, TSPException, FchainException {
		try {
			SimpleDateFormat dateFormat = new SimpleDateFormat("yyyyMMddHHmmss");
			byte[] byteTimeStamp = Util.base64Dec(dto.getTst());
			TimeStampToken token = Util.byteToTimeStamp(byteTimeStamp); //TST토큰
			String pdfTokenHash = dto.getPdfTokenHash(); //토큰삽입PDF해쉬
			String pdfHash = dto.getPdfHash(); //원본PDF해쉬
			
			TimeStampTokenInfo TSTInfo = token.getTimeStampInfo();
			String tokenGenTime = dateFormat.format(TSTInfo.getGenTime()); //토큰생성시간 

			//5-1.블록체인에 보낼 데이터 생성 
			JSONObject obj = new JSONObject();
			JSONObject obj2 = new JSONObject(); 

			obj.put("PdfTokenHash", pdfTokenHash);
			obj2.put("PdfHash", pdfHash);
			obj2.put("DocuSeq", "3");
			obj2.put("Tst", dto.getTst());
			obj2.put("IssuerDate", tokenGenTime); //보낼데이터(obj) 생성 끝 
			obj.put("TsaData", obj2);

			fabricSDK.invokeTrasaction(obj);			
		} catch(ContractException e) {
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
