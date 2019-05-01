package io._focuson.libdte;

import https.maullin_sii_cl.dtews.crseed_jws.CrSeed;
import https.maullin_sii_cl.dtews.crseed_jws.CrSeedService;
import https.maullin_sii_cl.dtews.gettokenfromseed_jws.GetTokenFromSeedService;
import io._focuson.libdte.utils.SignUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.TransformerException;
import java.io.File;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyException;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Logger;

public class Connection {
    private final static Logger LOGGER = Logger.getLogger(Connection.class.getCanonicalName());


    private String getSeed() {
        CrSeedService crSeedService = new CrSeedService();

        // se recupera la semilla de el SII
        CrSeed crSeed = crSeedService.getCrSeed();
        String seed = crSeed.getSeed();
        // se recupera el valor desde el elemento Semilla, enviado por el SII
        return getTagValue(seed, "SEMILLA");

    }

    public String getToken(File key, String password) {
        String result = null;

        // generar XML con el numero de semilla y la estructura basica a firmar
        DocumentBuilderFactory docFactory = DocumentBuilderFactory.newInstance();
        DocumentBuilder docBuilder;

        try {
            docBuilder = docFactory.newDocumentBuilder();
            Document doc = docBuilder.newDocument();
            //SE CREA XML PARA FIRMAR, EN MEMORIA
            // elemento principal

            Element rootElement = doc.createElement("getToken");
            doc.appendChild(rootElement);

            // items
            Element item = doc.createElement("item");
            rootElement.appendChild(item);

            Element semilla = doc.createElement("Semilla");
            String seed = getSeed();

            LOGGER.info("VALOR SEMILLA WS SII : " + seed);

            // Semilla,se agrega el valor de la semilla devuelto por el WS de el SII
            semilla.appendChild(doc.createTextNode(seed));
            item.appendChild(semilla);

            // SE FIRMA EL DOCUMENTO XML
            String docFirmado = SignUtils.sign(doc, key, password);
            LOGGER.info("XML FIRMADO : " + docFirmado);

            // se conecta al WS
            GetTokenFromSeedService tokenService = new GetTokenFromSeedService();
            String token = tokenService.getGetTokenFromSeed().getToken(docFirmado);

            LOGGER.info("TOKEN RECUPERADO : " + token);
            result = token;

        } catch (ParserConfigurationException | TransformerException | NoSuchAlgorithmException
                | InvalidAlgorithmParameterException | KeyException
                | MarshalException | XMLSignatureException e) {
            e.printStackTrace();
        }
        return result;

    }

    private static String getTagValue(String xml, String tagName) {
        return xml.split("<" + tagName + ">")[1].split("</" + tagName + ">")[0];
    }
}
