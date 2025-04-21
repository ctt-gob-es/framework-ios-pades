package es.gob.afirma.ios;

/**
 * Errores que puede notificar la operaci&oacute;n de firma.
 */
public class SignatureError {

	/** Error desconocido. */
	public static final int UNKNOWN = 1;

	/** Error desconocido grave. */
	public static final int UNKNOWN_SEVERE = 2;

	/** Operaci&oacute;n cancelada por el usuario. */
	public static final int CANCELLED = 3;

	/** Error al leer o escribir datos. */
	public static final int INPUT_OUTPUT_ERROR = 4;

	/** No se ha podido realizar la accion porque el PDF est&aacute; protegido por contrase&ntilde;a. */
	public static final int PASSWORD_PROTECTED = 5;

	/** La contrase&ntilde; proporcionada no es correcta. */
	public static final int BAD_PASSWORD = 6;

	/** El documento no es un PDF soportado. */
	public static final int INVALID_PDF = 7;

	/** Se ha seleccionado una p&aacute;gina no v&aacute;lida para la r&uacute;brica de la firma. */
	public static final int INVALID_PAGE = 8;

	/** Se ha seleccionado una pposici&oacute;n no v&aacute;lida para la r&uacute;brica de la firma. */
	public static final int INVALID_RUBRIC_POSITION = 9;

	/** Se ha detectado que un formulario se ha modificado despu&eacute;s de una firma anterior. */
	public static final int FORM_MODIFIED = 10;

	/** Se ha detectado que el documento puede haber sido modificado despu&eacute;s de una firma anterior. */
	public static final int SUSPECTED_PSA = 11;

	/** Se ha detectado que el documento contiene firmas anteriores sin registrar. */
	public static final int UNREGISTER_SIGNATURES = 12;

	/** El documento esta certificado y puede que no permita nuevas firmas. */
	public static final int CERTIFIED_DOCUMENT = 13;
}
