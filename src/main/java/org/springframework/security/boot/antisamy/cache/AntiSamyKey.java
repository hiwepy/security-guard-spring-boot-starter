package org.springframework.security.boot.antisamy.cache;
/**
 * AntiSamyKey.
 *
 * @author [@Loong Wan](https://github.com/loong10k)
 * @since 1.0.0
 */

public abstract class AntiSamyKey {

	/** 多个configuration的情况下的分割符号*/
	public final static String  MODULE_SPLIT_KEY = "moduleSplit";
	/** 解析扫描器type取值key*/
	public final static String SCANTYPE_KEY = "scanType";
	/** 需要过滤的requestpath的正则匹配表达式取值key*/
	public final static String INCLUDE_PATTERNS_KEY = "includePatterns";
	/** 不需要过滤的requestpath的正则匹配表达式取值key*/
	public final static String EXCLUDE_PATTERNS_KEY = "excludePatterns";
	/** default的防XSS攻击的规则configuration取值key*/
	public final static String DEFAULT_POLICY_KEY = "defaultPolicy";
	/** 防XSS攻击的模块对应的规则configuration取值key*/
	public final static String  POLICY_MAPPINGS_KEY = "policyMappings";
	/** 使用 x.properties文件来configuration防XSS攻击时相关参数的configuration文件path */
	public final static String  CONFIG_LOCATION_KEY = "configLocation";
	
}
