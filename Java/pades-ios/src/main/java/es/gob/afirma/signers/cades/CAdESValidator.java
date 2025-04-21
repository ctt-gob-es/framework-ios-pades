/* Copyright (C) 2011 [Gobierno de Espana]
 * This file is part of "Cliente @Firma".
 * "Cliente @Firma" is free software; you can redistribute it and/or modify it under the terms of:
 *   - the GNU General Public License as published by the Free Software Foundation;
 *     either version 2 of the License, or (at your option) any later version.
 *   - or The European Software License; either version 1.1 or (at your option) any later version.
 * You may contact the copyright holder at: soporte.afirma@seap.minhap.es
 */

package es.gob.afirma.signers.cades;

import java.io.IOException;
import java.util.Enumeration;
import java.util.logging.Logger;

import org.spongycastle.asn1.ASN1InputStream;
import org.spongycastle.asn1.ASN1ObjectIdentifier;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.ASN1Set;
import org.spongycastle.asn1.ASN1TaggedObject;
import org.spongycastle.asn1.DEROctetString;
import org.spongycastle.asn1.cms.Attribute;
import org.spongycastle.asn1.cms.SignedData;
import org.spongycastle.asn1.cms.SignerInfo;
import org.spongycastle.asn1.pkcs.PKCSObjectIdentifiers;

import es.gob.afirma.core.signers.AOSignConstants;

/** Agrupa distintos m&eacute;todos de verificaci&oacute;n estructural de datos CAdES. Es importante rese&ntilde;ar que las
 * validaciones son &uacute;nicamente a nivel de estructura, y no a nivel de validez de la propia firma electr&oacute;ca o
 * los firmantes. */
public final class CAdESValidator {

    private static final Logger LOGGER = Logger.getLogger("es.gob.afima"); //$NON-NLS-1$

    private CAdESValidator() {
        // No permitimos la instanciacion
    }

    private static Enumeration<?> getCAdESObjects(final byte[] data) throws IOException {
    	try (
			final ASN1InputStream is = new ASN1InputStream(data);
		) {
    		final ASN1Sequence dsq = (ASN1Sequence) is.readObject();
    		return dsq.getObjects();
    	}
    }

    /** Verifica si los datos proporcionados se corresponden con una estructura de tipo <i>Data</i>.
     * @param data Datos PKCS#7/CMS/CAdES.
     * @return <code>true</code> si los datos proporcionados se corresponden con una estructura de tipo <i>Data</i>,
     * <code>false</code> en caso contrario.
     * @throws IOException En caso de problemas leyendo el fichero */
	@SuppressWarnings("unused")
	static boolean isCAdESData(final byte[] data) throws IOException {

        // LEEMOS EL FICHERO QUE NOS INTRODUCEN
        final Enumeration<?> e = getCAdESObjects(data);

        // Elementos que contienen los elementos OID Data
        final ASN1ObjectIdentifier doi = (ASN1ObjectIdentifier) e.nextElement();
        if (!doi.equals(PKCSObjectIdentifiers.data)) {
            return false;
        }

        // Contenido de Data
        final ASN1TaggedObject doj = (ASN1TaggedObject) e.nextElement();

        try {
            /* Los valores de retorno no se usan, solo es para verificar que la
             * conversion ha sido correcta. De no ser asi, se pasaria al manejo
             * de la excepcion. */
            new DEROctetString(doj.getObject());

        }
        catch (final Exception ex) {
        	LOGGER.fine("Los datos proporcionados no son de tipo Data: " + ex); //$NON-NLS-1$
            return false;
        }

        return true;
    }

    /** Verifica si los datos proporcionados se corresponden con una estructura de tipo <i>SignedData</i>.
     * @param data Datos PKCS#7/CMS/CAdES.
     * @param enforceCAdES Si se establece a <code>true</code> se comprueba que los SignerInfos sean expl&iacute;citamente
     *                     de tipo CAdES, si se establece a <code>false</code> no se comprueba, por lo que se aceptan
     *                     <code>SignedData</code> de CMS y PKCS#7.
     * @return <code>true</code> si los datos proporcionados se corresponden con una estructura de tipo <i>SignedData</i>,
     * <code>false</code> en caso contrario. */
    public static boolean isCAdESSignedData(final byte[] data, final boolean enforceCAdES) {
        try {
            // LEEMOS EL FICHERO QUE NOS INTRODUCEN
            final Enumeration<?> e = getCAdESObjects(data);

            // Elementos que contienen los elementos OID SignedData
            final ASN1ObjectIdentifier doi = (ASN1ObjectIdentifier) e.nextElement();
            if (!doi.equals(PKCSObjectIdentifiers.signedData)) {
            	LOGGER.fine(
    				"Los datos proporcionados no son de tipo SignedData de CAdES (no esta declarado el OID de SignedData)" //$NON-NLS-1$
				);
        		return false;
            }

            // Contenido de SignedData
            final ASN1TaggedObject doj = (ASN1TaggedObject) e.nextElement();
            final ASN1Sequence datos = (ASN1Sequence) doj.getObject();
            final SignedData sd = SignedData.getInstance(datos);

            final ASN1Set signerInfosSd = sd.getSignerInfos();

            if (enforceCAdES) {
	            for (int i = 0; i < signerInfosSd.size(); i++) {
	            	if (!verifySignerInfo(SignerInfo.getInstance(signerInfosSd.getObjectAt(i)))) {
	            		LOGGER.fine(
	        				"Los datos proporcionados no son de tipo SignedData de CAdES (al menos un SignerInfo no se ha declarado de tipo CAdES)" //$NON-NLS-1$
	    				);
	            		return false;
	            	}
	            }
            }

        }
        catch (final Exception ex) {
        	LOGGER.fine("Los datos proporcionados no son de tipo SignedData de CAdES: " + ex); //$NON-NLS-1$
            return false;
        }

        return true;
    }

    /** Verifica que los <code>SignerInfos</code> tengan el par&aacute;metro
     * que identifica que los datos son de tipo CAdES.
     * @param si <code>SignerInfo</code> para la verificaci&oacute;n del par&aacute;metro
     *        adecuado.
     * @return si contiene el par&aacute;metro. */
    private static boolean verifySignerInfo(final SignerInfo si) {
        boolean isSignerValid = false;
        final ASN1Set attrib = si.getAuthenticatedAttributes();
        final Enumeration<?> e = attrib.getObjects();
        Attribute atribute;
        while (e.hasMoreElements()) {
        	final ASN1Sequence seq = (ASN1Sequence) e.nextElement();
            atribute = new Attribute(
        		(ASN1ObjectIdentifier)seq.getObjectAt(0),
        		(ASN1Set)seq.getObjectAt(1)
    		);

            // Si tiene la politica es CADES.
            if (atribute.getAttrType().equals(PKCSObjectIdentifiers.id_aa_signingCertificate) ||
                atribute.getAttrType().equals(PKCSObjectIdentifiers.id_aa_signingCertificateV2)) {
                	isSignerValid = true;
            }
        }
        return isSignerValid;
    }

    /** Comprueba que un archivo cumple con una estructura de tipo CAdES.
     * Se permite la verificaci&oacute;n de los siguientes tipos de estructuras:
     * <ul>
     *  <li>Data</li>
     *  <li>Signed Data</li>
     *  <li>Digested Data</li>
     *  <li>Encrypted Data</li>
     *  <li>Enveloped Data</li>
     *  <li>Signed and Enveloped Data</li>
     * </ul>
     * @param signData Datos que se desean comprobar.
     * @param type Tipo de firma o estructura CMS que se quiere verificar. Los valores aceptados son
     *             <ul>
     *              <li><code>AOSignConstants.CMS_CONTENTTYPE_DATA</code></li>
     *              <li><code>AOSignConstants.CMS_CONTENTTYPE_SIGNEDDATA</code></li>
     *              <li><code>AOSignConstants.CMS_CONTENTTYPE_ENCRYPTEDDATA</code></li>
     *              <li><code>AOSignConstants.CMS_CONTENTTYPE_ENVELOPEDDATA</code></li>
     *              <li><code>AOSignConstants.CMS_CONTENTTYPE_SIGNEDANDENVELOPEDDATA</code></li>
     *              <li><code>AOSignConstants.CMS_CONTENTTYPE_DIGESTEDDATA</code></li>
     *             </ul>
     * @param enforceCAdESSignedData Si se establece a <code>true</code> se comprueba que los SignerInfos sean
     *                               expl&iacute;citamente de tipo CAdES, si se establece a <code>false</code> no
     *                               se comprueba, por lo que se aceptan <code>SignedData</code> de CMS y PKCS#7.
     *                               Solo aplica a comprobaciones de <code>SignedData</code>.
     * @return <code>true</code> si los datos proporcionados se corresponden con la estructura CAdES
     *         indicada, <code>false</code> en caso contrario.
     * @throws IOException Si ocurren problemas en la lectura de la firma */
    public static boolean isCAdESValid(final byte[] signData, final String type, final boolean enforceCAdESSignedData) throws IOException {
        if (type.equals(AOSignConstants.CMS_CONTENTTYPE_DATA)) {
			return CAdESValidator.isCAdESData(signData);
        }
        else if (type.equals(AOSignConstants.CMS_CONTENTTYPE_SIGNEDDATA)) {
			return CAdESValidator.isCAdESSignedData(signData, enforceCAdESSignedData);
        }
        LOGGER.fine("Tipo de contenido CADES no reconocido"); //$NON-NLS-1$
        return false;
    }

    /** Comprueba que un archivo cumple con una estructura de tipo CAdES.
     * Se permite la verificaci&oacute;n de los siguientes tipos de estructuras:
     * <ul>
     *  <li>Data</li>
     *  <li>Signed Data</li>
     *  <li>Digested Data</li>
     *  <li>Encrypted Data</li>
     *  <li>Enveloped Data</li>
     *  <li>Signed and Enveloped Data</li>
     * </ul>
     * @param data Datos que se desean comprobar.
     * @param enforceCAdESSignedData Si se establece a <code>true</code> se comprueba que los SignerInfos sean
     *                               expl&iacute;citamente de tipo CAdES, si se establece a <code>false</code> no
     *                               se comprueba, por lo que se aceptan <code>SignedData</code> de CMS y PKCS#7.
     *                               Solo aplica a comprobaciones de <code>SignedData</code>.
     * @return <code>true</code> si los datos proporcionados se corresponden con la estructura CAdES
     *         indicada, <code>false</code> en caso contrario.
     * @throws IOException Si ocurren problemas en la lectura de los datos. */
    public static boolean isCAdESValid(final byte[] data, final boolean enforceCAdESSignedData) throws IOException {
        // si se lee en el CMSDATA, el inputstream ya esta leido y en los demas
        // siempre sera nulo
        if (data == null) {
            LOGGER.warning("Se han introducido datos nulos para su comprobacion"); //$NON-NLS-1$
            return false;
        }

		// Comprobamos si su contenido es de tipo DATA
        boolean valido = CAdESValidator.isCAdESData(data);
        // Comprobamos si su contenido es de tipo SIGNEDDATA
        if (!valido) {
			valido = CAdESValidator.isCAdESSignedData(data, enforceCAdESSignedData);
        }
        return valido;
    }
}
