package com.finger.tsa.tsa.controller;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.TimeoutException;

import org.bouncycastle.cms.CMSException;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.tsp.TSPException;
import org.json.simple.parser.ParseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import com.finger.tsa.common.advice.FchainException;
import com.finger.tsa.common.response.ResponseService;
import com.finger.tsa.common.response.SingleResult;
import com.finger.tsa.dto.RequestDto;
import com.finger.tsa.dto.ResponseDto;

import com.finger.tsa.tsa.service.TSAService;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@RestController
public class TSAController {

	private static final Logger logger = LoggerFactory.getLogger( TSAController.class );
	
	private final ResponseService responseService;
	private final TSAService tsaservice; 


	/**
	 * @see 전자계약문서 시점확인 - 등록
	 * @param PDF파일을 Binary Strings으로 변환한 값 
	 * @return PDF파일에 TimeStampToken이 삽입된 Binary Strings
	 * @author 김문수
	 * @throws GeneralSecurityException 
	 * @throws CMSException 
	 * @throws FchainException 
	 * @throws InterruptedException 
	 * @throws TimeoutException 
	 * @throws IOException 
	 * @throws TSPException 
	 * @throws NullPointerException 
	 * @throws OperatorCreationException 
	 * @throws IllegalArgumentException 
	 */
	@PostMapping("/v1/tsa/gettoken")
	public SingleResult<String> getFileIncludedToken(@RequestBody RequestDto dto) throws IllegalArgumentException, OperatorCreationException, NullPointerException, TSPException, IOException, TimeoutException, InterruptedException, FchainException, CMSException, GeneralSecurityException   {
		
		logger.debug("#### START getFileIncludedToken ####");
		String result = tsaservice.getFileIncludedToken(dto);
		return responseService.getSingleResult(result);

	}
	
	/**
	 * @see 전자계약문서 시점확인 - 검증 
	 * @param PDF에 TimeStampToken이 포함된 파일을 Binary Strings으로 변환한 값 
	 * @return 검증확인값
	 * @author 김문수
	 * @throws FchainException 
	 * @throws IOException 
	 * @throws NoSuchAlgorithmException 
	 * @throws ParseException 
	 */
	@PostMapping("/v1/tsa/verify")
	public SingleResult<ResponseDto> verifyPdfFile(@RequestBody RequestDto dto) throws NoSuchAlgorithmException, IOException, FchainException, ParseException{
		
		logger.debug("#### START verifyPdfFile ####");
		ResponseDto resDto = tsaservice.verifyPdfFile(dto);
		return responseService.getSingleResult(resDto);

	}
	
	/**
	 * @see 서버의 상태확인용 
	 * @return true
	 */
	@PostMapping("/status")
	public boolean returnResponse() {
		logger.debug("#### START returnResponse ####");
		return true; 
	}
	

}
