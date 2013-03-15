<?php
/**
 * AController
 *
 * Created: 25-jan-2013
 * 
 * @copyright (c) 2013, Denit Serp <denit.serp at gmail.com>
 */
class AController extends Controller {
	
	public function init()
	{
		Yii::app()->apiAuth;
		return parent::init();
	}
	
	/**
	 * Returns the authentication rules for this controller.
	 * Override this method if you use the {@link filterApiAuthControl authControl} filter.
	 * @return array list of authentication rules. See {@link CAccessControlFilter} for details about rule specification.
	 */
	public function apiAuthRules()
	{
		return array();
	}
	
	/**
	 * The filter method for 'accessControl' filter.
	 * This filter is a wrapper of {@link CAccessControlFilter}.
	 * To use this filter, you must override {@link accessRules} method.
	 * @param CFilterChain $filterChain the filter chain that the filter is on.
	 */
	public function filterApiAuth($filterChain)
	{
		ApiAuth::beginProfile("ext.apiAuth.AController.filterApiAuth()", "ext.apiAuth.AController");
		
		$filter=new AAuthFilter;
		$filter->setRules($this->apiAuthRules());
		$filter->filter($filterChain);
		
		ApiAuth::endProfile("ext.apiAuth.AController.filterApiAuth()", "ext.apiAuth.AController");
	}
	
}