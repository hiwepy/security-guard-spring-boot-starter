 package org.springframework.security.boot.antisamy.cache;


 import org.springframework.security.boot.antisamy.AntisamyProperties;
 import org.owasp.validator.html.AntiSamy;
 import org.owasp.validator.html.Policy;
 import org.owasp.validator.html.PolicyException;

 import java.util.concurrent.ConcurrentHashMap;
 import java.util.concurrent.ConcurrentMap;

/**
 * AntiSamy 对象cache管理
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
public class AntiSamyCacheManager {
	
	private volatile static AntiSamyCacheManager singleton;
	protected static ConcurrentMap<Policy, AntiSamy> COMPLIED_ANTISAMY = new ConcurrentHashMap<Policy, AntiSamy>();
	/**
	 * get Instance.
	 *
	 * @param policyCacheManager the policy cache manager
	 * @return the result
	 */
	protected PolicyCacheManager policyCacheManager;
	
	/**
	 * get Instance.
	 *
	 * @param policyCacheManager the policy cache manager
	 * @return the result
	 */
	public static AntiSamyCacheManager getInstance(PolicyCacheManager policyCacheManager) {
		if (singleton == null) {
			synchronized (AntiSamyCacheManager.class) {
				if (singleton == null) {
					singleton = new AntiSamyCacheManager(policyCacheManager);
				}
			}
		}
		return singleton;
	}
	
	private AntiSamyCacheManager(PolicyCacheManager policyCacheManager){
		this.policyCacheManager = policyCacheManager;
	}
	
	/**
	 * get Xss Anti Samy Wrapper.
	 *
	 * @param relativePath the relative path
	 * @param scanType the scan type
	 * @param policyHeaders the policy headers
	 * @return the result
	 * @throws PolicyException if an error occurs
	 */
	public AntiSamyWrapper getXssAntiSamyWrapper(String relativePath, int scanType, String[] policyHeaders) throws PolicyException{
		Policy xssPolicy = this.policyCacheManager.getXssPolicy(relativePath);
		return getXssAntiSamyWrapper(xssPolicy, scanType, policyHeaders);
	}
	
	/**
	 * get Xss Anti Samy Wrapper.
	 *
	 * @param xssPolicy the xss policy
	 * @param scanType the scan type
	 * @param policyHeaders the policy headers
	 * @return the result
	 * @throws PolicyException if an error occurs
	 */
	public AntiSamyWrapper getXssAntiSamyWrapper(Policy xssPolicy, int scanType, String[] policyHeaders) throws PolicyException {
		if(xssPolicy == null) {
			throw new PolicyException("Policy Not Found.");
		}
		AntiSamy ret = COMPLIED_ANTISAMY.get(xssPolicy);
		if (ret != null) {
			return new AntiSamyWrapper(ret, xssPolicy, scanType, policyHeaders);
		}
		ret = new AntiSamy(xssPolicy);
		AntiSamy existing = COMPLIED_ANTISAMY.putIfAbsent(xssPolicy, ret);
		if (existing != null) {
			ret = existing;
		}
		return new AntiSamyWrapper(ret, xssPolicy, scanType, policyHeaders);
	}

	/**
	 * get Default Anti Samy Wrapper.
	 *
	 * @param scanType the scan type
	 * @param policyHeaders the policy headers
	 * @return the result
	 * @throws PolicyException if an error occurs
	 */
	public AntiSamyWrapper getDefaultAntiSamyWrapper(int scanType, String[] policyHeaders) throws PolicyException {
		Policy xssPolicy = this.policyCacheManager.getXssPolicy(AntisamyProperties.DEFAULT_POLICY);
		return getXssAntiSamyWrapper(xssPolicy, scanType, policyHeaders);
	}
	
	/**
	 * destroy.
	 *
	 */
	public void destroy() {
		synchronized (COMPLIED_ANTISAMY) {
			policyCacheManager.destroy();
			COMPLIED_ANTISAMY.clear();
		}
	}
}

