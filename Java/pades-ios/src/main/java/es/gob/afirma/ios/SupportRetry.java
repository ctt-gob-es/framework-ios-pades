package es.gob.afirma.ios;

/**
 * Contiene la informaci&oacute;n necesaria para poder reintentar una operaci&oacute;n.
 */
public class SupportRetry {

	private final String key;
	private final String value;

	public SupportRetry(final String key, final String value) {
		this.key = key;
		this.value = value;
	}

	public String getKey() {
		return this.key;
	}

	public String getValue() {
		return this.value;
	}
}
