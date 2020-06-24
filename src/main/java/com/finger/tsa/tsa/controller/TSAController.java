package com.finger.tsa.tsa.controller;


import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;

import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;

import java.util.Date;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.TimeoutException;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;

import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.SignerInfoGenerator;

import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.OperatorCreationException;

import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampResponseGenerator;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.tsp.TimeStampTokenGenerator;

import org.hyperledger.fabric.gateway.ContractException;
import org.json.simple.parser.ParseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;

import org.springframework.context.annotation.Configuration;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

import org.springframework.web.bind.annotation.RestController;

import com.finger.tsa.common.advice.FchainException;
import com.finger.tsa.common.response.CommonResult;
import com.finger.tsa.common.response.ResponseService;
import com.finger.tsa.common.response.SingleResult;
import com.finger.tsa.tsa.dto.TSADto;
import com.finger.tsa.tsa.service.TSAService;

import com.finger.tsa.util.Util;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@RestController
@Configuration
public class TSAController {
	@Value("${pubKey}")
	private String PUBKEY; 
	@Value("${privKey}")
	private String PRIVKEY;
	private static final Logger logger = LoggerFactory.getLogger( TSAController.class );
	
	private final ResponseService responseService;
	private final TSAService tsaservice; 

	@PostMapping("/insertblc")
	public CommonResult insertBLC(@RequestBody TSADto dto) throws TimeoutException, InterruptedException, ParseException, IOException, CMSException, TSPException, FchainException {
		//pdf해쉬, 토큰삽입pdf해쉬, 토큰 받음. 
		//받은거 블록체인에 전달하고 응답값을 넘겨줌. 
		logger.debug("#### START insertBLC ####");
		tsaservice.insertBLC(dto);
		return responseService.getSuccessResult();
		
	}
	
	@PostMapping(value = "/")
	public byte[] genTokenResp(HttpServletRequest req) throws ContractException, TimeoutException, InterruptedException, ParseException, IOException, CMSException, TSPException, IllegalArgumentException, OperatorCreationException, NoSuchAlgorithmException, InvalidKeySpecException, NullPointerException, CertificateException {
		logger.debug("#### START genTokenResp ####");
		//TimeStampReq 를 수신. 
		//1.받은 TimeStamReq에 대한 확인 및 검증 수행. 
		//2.에러 발생시 해당 메세지를 에러처리하고 결과 전송후 종료 
		//3.성공적으로 수행시 TimeStampResp를 구성하는 변수들의값을 채우는 과정. 
		//4.서버와 클라간의 메시지 무결성을 보장하기위해 
		//TimeStampResp 구조체로부터 TSTInfo 구조체를 추출하고 
		//추출된 현재시각 정보인 genTime과 리 퀘스터가 보낸 TimeStampReq에 nonce값을 이용하여 
		//MAC값을 산출한 후 MAC값 계산시 이용한 알고리즘 식별자정보와 MAC값을 MacInfo구조체의 해당 필드에 설정 
		//5.MacInfo 구조체를 TSTInfo의 확장필드에 추가하여 
		//TimeStampResp구조체를 생성하여 응답. 

		InputStream in = req.getInputStream();
	    byte[] reqs = IOUtils.toByteArray(in); 
		TimeStampRequest request = new TimeStampRequest(reqs);

		TimeStampTokenGenerator tstg;
		SignerInfoGenerator signerInfo = new JcaSimpleSignerInfoGeneratorBuilder().build("SHA256withRSA",Util.getPrivateKey(PRIVKEY), Util.getPublicKey(PUBKEY));
		DigestCalculator digestCal = new JcaDigestCalculatorProviderBuilder().build().get(new AlgorithmIdentifier(new ASN1ObjectIdentifier(NISTObjectIdentifiers.id_sha256.getId())));
		ASN1ObjectIdentifier tsaPolicy = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.1");
		tstg = new TimeStampTokenGenerator(signerInfo, digestCal, tsaPolicy);

		TimeStampToken token;
		Date TokenGenTime = new Date();
		token = tstg.generate(request, BigInteger.ONE, TokenGenTime);
		Set<String> set = new HashSet<String>();
		set.add(NISTObjectIdentifiers.id_sha256.getId());
		TimeStampResponseGenerator resGen = new TimeStampResponseGenerator(tstg, set);
		
		TimeStampResponse res = resGen.generate(request, BigInteger.ONE, TokenGenTime);
		
		res.validate(request); //응답검증. 
		if( res.getStatus() != 0) {
			logger.error("TimeStampResponse Status:"+ res.getStatus());
			logger.error("TimeStamperResponse StatusString: "+ res.getStatusString());
			PKIFailureInfo failInfo = res.getFailInfo();
			if( failInfo != null) logger.error("fail info int value :"+failInfo.intValue()); 
			return failInfo.getEncoded();
		}
		logger.debug("#### END genTokenResp ####");
		return  res.getEncoded();

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
	@PostMapping("/verify")
	public SingleResult<TSADto> verifyPdfFile(@RequestBody TSADto dto) throws NoSuchAlgorithmException, IOException, FchainException, ParseException{
		
		logger.debug("#### START verifyPdfFile ####");
		TSADto resDto = tsaservice.verifyPdfFile(dto);
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
