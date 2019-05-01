package io._focuson.libdte.utils;

import org.w3c.dom.Document;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class SignUtils {

    private SignUtils() {}

    public static String sign(Document doc, File key, String password) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, KeyException,
            MarshalException, XMLSignatureException, TransformerException {


        XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");

        // Create a Reference to the enveloped document (in this case we are
        // signing the whole document, so a URI of "" signifies that) and
        // also specify the SHA1 digest algorithm and the ENVELOPED Transform.
        Reference ref = fac.newReference("", fac.newDigestMethod(DigestMethod.SHA1, null),
                Collections.singletonList(fac.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null)), null,
                null);

        // Create the SignedInfo
        SignedInfo si = fac.newSignedInfo(
                fac.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE, (C14NMethodParameterSpec) null),
                fac.newSignatureMethod(SignatureMethod.RSA_SHA1, null), Collections.singletonList(ref));

        // SE TRABAJA CON EL EL ALMACEN DE CERTIFICADOS DIGITALES
        KeyStore ks = null;
        X509Certificate cert = null;
        KeyStore.PrivateKeyEntry keyEntry = null;
        try {
            ks = KeyStore.getInstance("JKS");
            ks.load(new FileInputStream(key), password.toCharArray());
            String alias = ks.aliases().nextElement();
            keyEntry = (KeyStore.PrivateKeyEntry) ks.getEntry(alias,new KeyStore.PasswordProtection(password.toCharArray()));
            cert = (X509Certificate) keyEntry.getCertificate();

        } catch (KeyStoreException | CertificateException | IOException | UnrecoverableEntryException e) {
            e.printStackTrace();
        }

        //se crea unn KeyFactory
        KeyInfoFactory kif = fac.getKeyInfoFactory();
        //se usa la clave publica para firmar
        KeyValue kv = kif.newKeyValue(cert.getPublicKey());

        // Create the KeyInfo containing the X509Data.
        List<X509Certificate> x509Content = new ArrayList<>();
        x509Content.add(cert);
        X509Data xd = kif.newX509Data(x509Content);

        // en una lista se agrega el KeyValue y el certificado X509Data a el KEYINFO
        List xml_tag_list = new ArrayList();
        xml_tag_list.add(kv); //TAG KeyValue
        xml_tag_list.add(xd); //TAG X509Data

        KeyInfo ki = kif.newKeyInfo(xml_tag_list);

        // Create a DOMSignContext and specify the RSA PrivateKey and
        // location of the resulting XMLSignature's parent element
        DOMSignContext dsc = new DOMSignContext(keyEntry.getPrivateKey(), doc.getDocumentElement());

        // Create the XMLSignature (but don't sign it yet)
        XMLSignature signature = fac.newXMLSignature(si, ki);

        // Marshal, generate (and sign) the enveloped signature
        signature.sign(dsc);

        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer trans = tf.newTransformer();
        trans.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");

        StringWriter writer = new StringWriter();
        trans.transform(new DOMSource(doc), new StreamResult(writer));

        return "<?xml version=\"1.0\"?>" + writer.getBuffer().toString().trim();
    }
}
