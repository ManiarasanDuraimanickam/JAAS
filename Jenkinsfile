#!/usr/bin/env groovy


properties([[$class: 'ParametersDefinitionProperty', parameterDefinitions: [ 
[$class: 'hudson.model.StringParameterDefinition', name: 'PHASE', defaultValue: "BUILD"],
[$class: 'hudson.model.StringParameterDefinition', name: 'TARGET_ENV', defaultValue: "DEV"],
[$class: 'hudson.model.StringParameterDefinition', name: 'K8S_CLUSTER_URL',defaultValue: ""],
[$class: 'hudson.model.StringParameterDefinition', name: 'K8S_CONTEXT',defaultValue: "default"],
[$class: 'hudson.model.StringParameterDefinition', name: 'K8S_USERNAME',defaultValue: ""],
[$class: 'hudson.model.PasswordParameterDefinition', name: 'K8S_PASSWORD',defaultValue: ""],
[$class: 'hudson.model.PasswordParameterDefinition', name: 'K8S_TOKEN',defaultValue: ""],
[$class: 'hudson.model.StringParameterDefinition', name: 'K8S_NAME',defaultValue: "DEV"],
[$class: 'hudson.model.StringParameterDefinition', name: 'K8S_PODS_REPLICAS',defaultValue: "1"],
[$class: 'hudson.model.StringParameterDefinition', name: 'K8S_SERVICE_ACCOUNT',defaultValue: "default"],
[$class: 'hudson.model.BooleanParameterDefinition', name: 'USE_ROOT_NS',defaultValue: false],
[$class: 'hudson.model.StringParameterDefinition', name: 'BROKER_URL',defaultValue: "http://zlp25163.vci.att.com:30120"],
[$class: 'hudson.model.StringParameterDefinition', name: 'PACT_USERNAME', defaultValue: "pactadmin"],
[$class: 'hudson.model.PasswordParameterDefinition', name: 'PACT_PASSWORD', defaultValue: "pactadmin"],
[$class: 'hudson.model.StringParameterDefinition', name: 'CONSUMER', defaultValue: ""],
[$class: 'hudson.model.StringParameterDefinition', name: 'GIT_REPO_FOLDER',defaultValue: ""],
[$class: 'hudson.model.StringParameterDefinition', name: 'DEV_TEST_GIT_APP',defaultValue: ""],
[$class: 'hudson.model.StringParameterDefinition', name: 'DEV_TEST_SERVER_URL',defaultValue: ""],
[$class: 'hudson.model.StringParameterDefinition', name: 'LISA_PATH', defaultValue: "/opt/app/workload/tools/itko/server/9.5.1/Projects/"],
[$class: 'hudson.model.StringParameterDefinition', name: 'TEST_CASE_PATH',defaultValue: "/Tests/HelloTest.tst"],
[$class: 'hudson.model.StringParameterDefinition', name: 'SUITE_CASE_PATH', defaultValue: "/Tests/Suites/AllTestsSuite.ste"],
[$class: 'hudson.model.StringParameterDefinition', name: 'CONFIG_PATH', defaultValue: "/Configs/project.config"],
[$class: 'hudson.model.StringParameterDefinition', name: 'STAGING_DOC_PATH',defaultValue: "/Tests/StagingDocs/Run1User1Cycle.stg"],

[$class: 'hudson.model.StringParameterDefinition', name: 'ANS_ROLE',defaultValue: ""],
[$class: 'hudson.model.StringParameterDefinition', name: 'ANS_INVENTORY',defaultValue: "inventory/dev/hosts"],
[$class: 'hudson.model.StringParameterDefinition', name: 'GITPlaybookPATH', defaultValue: ""],
[$class: 'hudson.model.StringParameterDefinition', name: 'GITConfigRolePATH', defaultValue: ""],
[$class: 'hudson.model.StringParameterDefinition', name: 'SONAR_BREAKER_SKIP',defaultValue: "True"],
[$class: 'hudson.model.StringParameterDefinition', name: 'SONAR_BREAKER_QRY_INTERVAL',defaultValue: "7000"],
[$class: 'hudson.model.StringParameterDefinition', name: 'SONAR_BREAKER_QRY_MAXATTEMPTS',defaultValue: "100"],
[$class: 'hudson.model.StringParameterDefinition', name: 'ECO_PIPELINE_ID',defaultValue: ""],
[$class: 'hudson.model.StringParameterDefinition', name: 'BUILD_VERSION',defaultValue: ""]
]]]) 

/**
    jdk1.8 = fixed name for java
    M3 = fixed name for maven
    general_maven_settings = fixed name for maven settings Jenkins managed file
*/

echo "Build branch: ${env.BRANCH_NAME}"

node("docker") {
	stage 'Checkout'
	checkout scm
	
	pom = readMavenPom file: 'pom.xml'
	PROJECT_NAME = pom.properties['namespace'] + ":" + pom.artifactId;
//	env.SERVICE_NAME=pom.artifactId;
    env.APP_NAME=pom.artifactId;
	
	env.SERVICE_NAME=pom.properties['serviceArtifactName']
	env.VERSION=pom.version;

	env.ANS_ROLE=SERVICE_NAME+"_configrole"
	env.BUILDNUMBER_TIMESTAMP="${BUILD_NUMBER}"+"-"+"${currentBuild.timeInMillis}"
	
	echo "ANS_ROLE: ${ANS_ROLE}"
	
	LABEL_VERSION=pom.version.replaceAll(".", "-");
	echo "LabelVerion: " + LABEL_VERSION
	NAMESPACE=pom.properties['namespace']

	TARGET_ENV=TARGET_ENV.toLowerCase()
	if(params.USE_ROOT_NS)
	{
		env.KUBE_NAMESPACE=pom.properties['kube.namespace']
	}else{
		env.KUBE_NAMESPACE=pom.properties['kube.namespace']+"-"+TARGET_ENV
	}
	
	if(TARGET_ENV!="dev"){
		env.ANS_INVENTORY="inventory/"+TARGET_ENV+"/hosts"
		echo "ANS_INVENTORY: ${ANS_INVENTORY}"
	}
	
	
	REPLICA_COUNT="${params.K8S_PODS_REPLICAS}"
	env.IMAGE_NAME=pom.properties['docker.registry']+"/"+NAMESPACE+"/"+SERVICE_NAME+":latest"
	echo "Artifact: " + PROJECT_NAME
	env.DOCKER_HOST="tcp://localhost:4243"
	env.DOCKER_CONFIG="${WORKSPACE}/.docker"
	def branchName
	//This value can ideally come from pom as in IMAGE_NAME
	def dockerRegistry = "dockercentral.it.att.com:5100"
		
	if(params.BUILD_VERSION != "")
	{
		echo "BUILD VERSION Set : " + BUILD_VERSION
		currentBuild.displayName = "VERSION-${BUILD_VERSION}"
		currentBuild.description = "${BUILD_VERSION} ${ECO_PIPELINE_ID} ${PHASE}"
	}else{
		echo "BUILD VERSION Not Set, Use pom version: " + VERSION
		currentBuild.displayName = "VERSION-" +VERSION
		currentBuild.description = "${VERSION} ${ECO_PIPELINE_ID} ${PHASE}"
	}
	
	env.KUBECTL_OPTS="--server=${K8S_CLUSTER_URL} --insecure-skip-tls-verify=true  --password=${K8S_PASSWORD}  --username=${K8S_USERNAME}"
	env.K8S_SERVER_CREDENTIALS = " k8server=${K8S_CLUSTER_URL}:443 k8susername=${K8S_USERNAME} k8spassword=${K8S_PASSWORD} k8stoken=${K8S_TOKEN}"
	if ("${K8S_TOKEN}" != "" ) { 
 		env.KUBECTL_OPTS = "--server=${K8S_CLUSTER_URL} --insecure-skip-tls-verify=true  --token=${K8S_TOKEN}"
 		env.K8S_SERVER_CREDENTIALS =" k8server=${K8S_CLUSTER_URL}:443 k8susername= k8spassword= k8stoken=${K8S_TOKEN}" 		
 	}
 	
 	//echo "env.KUBECTL_OPTS=${KUBECTL_OPTS}"
 	//echo "K8S_SERVER_CREDENTIALS=${K8S_SERVER_CREDENTIALS}"
	
	//IST Variable
	LISA_PATH_NEW="${LISA_PATH}"+SERVICE_NAME
	
	// Create kubectl.conf  file here from Pipeline properties provided.
	
	withEnv(["PATH=${env.PATH}:${tool 'M3'}/bin:${tool 'jdk1.8'}/bin", "JAVA_HOME=${tool 'jdk1.8'}", "MAVEN_HOME=${tool 'M3'}"]) { 
			
		echo "JAVA_HOME=${env.JAVA_HOME}"
		echo "MAVEN_HOME=${env.MAVEN_HOME}"
		echo "PATH=${env.PATH}"

		wrap([$class: 'ConfigFileBuildWrapper', managedFiles: [
			[fileId: 'maven-settings.xml', variable: 'MAVEN_SETTINGS'],
			[fileId: 'sonar-secret.txt', variable: 'SONAR_SECRET'],
			[fileId: 'sonar.properties', variable: 'SONAR_PROPERTIES']
			]]) {
			
			 branchName = (env.BRANCH_NAME ?: "master").replaceAll(/[^0-9a-zA-Z_]/, "-")
			
			
			if ("${PHASE}" == "BUILD" || "${PHASE}" == "BUILD_DEPLOY" ) { 
			
			    stage 'Compile' 
		    	sh 'mvn -DskipTests -Dmaven.test.skip=true -s $MAVEN_SETTINGS -Ddummy.prop=$SONAR_PROPERTIES clean compile' 
 
				stage 'Unit Test' 
	    		sh 'mvn -s $MAVEN_SETTINGS verify -P all-tests' 
 
				stage 'Package' 
		    	sh 'mvn -DskipTests -Dmaven.test.skip=true -s $MAVEN_SETTINGS package' 
 
				stage 'Verify' 
		    	sh 'mvn -DskipTests -Dmaven.test.skip=true -s $MAVEN_SETTINGS verify' 
				
				stage ('Quality Scan and QG1')
				{
					def props = readProperties file: "${env.SONAR_PROPERTIES}"
			//		sh 'mvn help:effective-settings help:system help:effective-pom  -Dsonar.host.url=' + props['sonar.host.url'] + ' -Dsonar.att.motsid=' + props['sonar.att.motsid'] + ' -Dsonar.projectKey=' + props['sonar.att.motsid'] + ':' + PROJECT_NAME + ' -Dsonar.projectName=' + props['sonar.att.motsid'] + ':' + PROJECT_NAME + ' -Dsonar.projectDescription=' + props['sonar.att.motsid'] + ':' + PROJECT_NAME + ' -Dsonar.login=' + props['sonar.login'] + ' -Dsonar.password=' + props['sonar.password'] + ' -Dsonar.att.view.type=' + props['sonar.att.view.type'] + ' -Dsonar.att.dependencycheck.tattletale.java.command=' + props['sonar.att.dependencycheck.tattletale.java.command'] + ' -Dsonar.att.dependencycheck.tattletale.sourceDirectory.path=' + props['sonar.att.dependencycheck.tattletale.sourceDirectory.path'] + ' -Dsonar.att.dependencycheck.tattletale.destinationDirectory.path=' + props['sonar.att.dependencycheck.tattletale.destinationDirectory.path'] + ' -Dsonar.att.tattletale.base.folder=' + props['sonar.att.tattletale.base.folder'] +' -Dsonar.att.tattletale.binaries.folder=' + props['sonar.att.tattletale.binaries.folder'] +' -Dsonar.att.tattletale.enabled=' + props['sonar.att.tattletale.enabled']+ ' -Dsonar.buildbreaker.skip=${SONAR_BREAKER_SKIP} -s $MAVEN_SETTINGS sonar:sonar'
				}
				
	           if ("${DEV_TEST_GIT_APP}" != "") { 
				
				stage("CADev Repo Update") {
				   def GitinvokeURL = "${DEV_TEST_GIT_APP}/gitapp/service/git/push?gitUrl=${GIT_REPO_FOLDER}/${SERVICE_NAME}"
				   sh "curl -i -X GET  \'${GitinvokeURL}\'"
				}
								
 				stage("Component Test Using CA DEV TEST") {
				
				   def invokeURL = "${DEV_TEST_SERVER_URL}/lisa-invoke/runTest?testCasePath=${LISA_PATH_NEW}${TEST_CASE_PATH}&stagingDocPath=${LISA_PATH_NEW}${STAGING_DOC_PATH}"
				   sh "curl -i \'${invokeURL}\'"
				   invokeURL = "${DEV_TEST_SERVER_URL}/lisa-invoke/runSuite?suitePath=${LISA_PATH_NEW}${SUITE_CASE_PATH}&configPath=${LISA_PATH_NEW}${CONFIG_PATH}"
				   sh "curl -i \'${invokeURL}\'"
				} 
				}
				
				stage 'Component Test Using Mockito'
		    	sh 'mvn -s $MAVEN_SETTINGS -Dtest=ITComponentTest test'
		    	
				stage 'Publish Artifact'
				//sh 'docker ps'
	    		sh 'mvn -DskipTests -Dmaven.test.skip=true -Dhttps.protocols="TLSv1" -Djavax.net.ssl.trustStore="/opt/app/aft/aftswmnode/etc/cacerts.jks" -Djavax.net.ssl.trustStorePassword="f22723cffdbd2fff1cb3c558677a7684" -Djavax.net.ssl.keyStore="/opt/app/aft/aftswmnode/etc/cacerts.jks" -Djavax.net.ssl.keyStorePassword="f22723cffdbd2fff1cb3c558677a7684" -s $MAVEN_SETTINGS -U docker:build docker:push'
	    	
	    	} 
 
			if ("${PHASE}" == "BUILD_DEPLOY" || "${PHASE}" == "DEPLOY" || "${PHASE}" == "CONFIG") { 
				 // deploy to k8s
				 				 
				stage ('Clone playbook and configrole') {
				 	
				 		// read values captured at the generate time
						env.REPO_PROJECT = readFile './repoproject.txt'
						env.REPO_PROJECT= "${REPO_PROJECT.trim()}"
						// put some if conditions to use below values if empty above. 
						if(params.GITPlaybookPATH==""){
							GITPlaybookPATH="https://codecloud.web.att.com/scm/"+"${REPO_PROJECT}"+"/"+SERVICE_NAME+"_playbook.git"
						}
						echo "GITPlaybookPATH: ${GITPlaybookPATH}"
						if(params.GITConfigRolePATH==""){
							GITConfigRolePATH="https://codecloud.web.att.com/scm/"+"${REPO_PROJECT}"+"/"+SERVICE_NAME+"_configrole.git"
						}
						echo "GITConfigRolePATH: ${GITConfigRolePATH}"	
						
						env.dockermechid = readFile './dockerbuilduser.txt'
						env.dockermechid = "${dockermechid.trim()}"
						env.repogitid = readFile './repogitid.txt'
						env.repogitid = "${repogitid.trim()}"	
				 		echo "repogitid : ${repogitid}"
				 	
					 withCredentials([usernamePassword(credentialsId: env.repogitid, usernameVariable: 'ITS_SECRET_USERNAME', passwordVariable: 'ITS_SECRET_PASSWORD')]) {
					 env.DOCKER_HOST='unix:///var/run/docker.sock'
					 env.ANS_HOST = params.ANS_HOST ?: new URL("${params.K8S_CLUSTER_URL}").getHost()
					 
					 sh 'rm -rf playbook'
						
	                     dir('playbook') {
	                        git url: "${GITPlaybookPATH}", credentialsId: "${repogitid}"
	                    }
						
						
	                    dir("playbook/roles/${ANS_ROLE}") {
	                        if (branchName != 'master'){
	                         echo "branchName: ${branchName}"
	                         	 git url: "${GITConfigRolePATH}", credentialsId: "${repogitid}", branch: "${branchName}"
	                         }
	                         else{
	                         echo "else branchName: ${branchName}"
	                         	git url: "${GITConfigRolePATH}", credentialsId: "${repogitid}"
	                         }
	                    }
					}
				}
				
					
					stage ('Deploy to Staging'){
					
					echo "dockermechid : ${dockermechid}"
					
					withCredentials([usernamePassword(credentialsId: env.dockermechid, passwordVariable: 'password', usernameVariable: 'username')]) {
			   			 sh "docker login -u ${username} -p ${password} -e ${username} ${dockerRegistry}"
						}
						
					sh 'docker pull dockercentral.it.att.com:5100/com.att.dockercentral.public/ansible:2.2'
																			
					if ("${PHASE}" == "CONFIG") {
					
					sh 'docker run -v $(pwd)/playbook:/home/aft/ansible  dockercentral.it.att.com:5100/com.att.dockercentral.public/ansible:2.2 ansible-playbook -e ANSIBLE_RETRY_FILES_ENABLED=false -i ${ANS_INVENTORY} --skip-tags=deploy --extra-vars "appname=${APP_NAME} msname=${SERVICE_NAME} kube_namespace=${KUBE_NAMESPACE} imagename=${IMAGE_NAME} version=${VERSION} buildnumber_timestamp=${BUILDNUMBER_TIMESTAMP} ${K8S_SERVER_CREDENTIALS}  ANS_HOST=${ANS_HOST}  ANS_ROLE=${ANS_ROLE}" deploy.yml'
					
					} else {
					
					sh 'docker run  -v $(pwd)/playbook:/home/aft/ansible   dockercentral.it.att.com:5100/com.att.dockercentral.public/ansible:2.2 ansible-playbook -e ANSIBLE_RETRY_FILES_ENABLED=false -i ${ANS_INVENTORY} --extra-vars "appname=${APP_NAME} msname=${SERVICE_NAME} kube_namespace=${KUBE_NAMESPACE} imagename=${IMAGE_NAME} version=${VERSION} buildnumber_timestamp=${BUILDNUMBER_TIMESTAMP} ${K8S_SERVER_CREDENTIALS}  ANS_HOST=${ANS_HOST}  ANS_ROLE=${ANS_ROLE}" deploy.yml'
					
					}
					
				}

			} 
						
			if ( "${PHASE}" == "CONTRACT_GENERATE") { 
              stage 'Contract Generate Publish and QG2'
              sh 'mvn -s $MAVEN_SETTINGS -Dtest=PactTestSuit test -DBROKER_URL=${BROKER_URL} -DuserName=${PACT_USERNAME} -Dpassword=${PACT_PASSWORD}' 
              sh 'mvn -s $MAVEN_SETTINGS pact:publish -DBROKER_URL=${BROKER_URL} -DuserName=${PACT_USERNAME} -Dpassword=${PACT_PASSWORD}' 
			}
			
            if ("${PHASE}" == "CONTRACT_VERIFY" ) {
               stage ('Contract Verify' ){
                 withEnv([
                        "APP_NAME=${SERVICE_NAME}",
                        "K8S_CTX=${K8S_CONTEXT}",
                        "APP_NS=${KUBE_NAMESPACE}",
                        "KUBECTL=/opt/app/kubernetes/v1.5.2/bin/kubectl",
						]) {
						def CLUSTER_URL=K8S_CLUSTER_URL.substring(8)
						
			NODE_PORT = sh (
                     script: '${KUBECTL}  get service ${APP_NAME} --namespace ${APP_NS} --context ${K8S_CTX} ${KUBECTL_OPTS} --output jsonpath={.spec.ports[*].nodePort}',
                      returnStdout: true
                      ).trim()
              if( "${CONSUMER}" == "") {
					sh "mvn -s $MAVEN_SETTINGS pact:verify -DBROKER_URL=${BROKER_URL} -DuserName=${PACT_USERNAME} -Dpassword=${PACT_PASSWORD} -DAPP_URL=${CLUSTER_URL} -DAPP_PORT=${NODE_PORT}"
				} else {
					sh "mvn -s $MAVEN_SETTINGS pact:verify -Dpact.filter.consumers=${CONSUMER} -DBROKER_URL=${BROKER_URL} -DuserName=${PACT_USERNAME} -Dpassword=${PACT_PASSWORD} -DAPP_URL=${CLUSTER_URL} -DAPP_PORT=${NODE_PORT}"
				}    
				          }
             }
             }
             
           if ("${PHASE}" == "INTEGRATION_TEST" || "${PHASE}" == "IST" || "${PHASE}" == "DEPLOY_IST"  ) {
			
				stage("CADev Repo Update") {
				   def GitinvokeURL = "${DEV_TEST_GIT_APP}/gitapp/service/git/push?gitUrl=${GIT_REPO_FOLDER}/${SERVICE_NAME}"
				   sh "curl -i -X GET  \'${GitinvokeURL}\'"
				}
				
				stage("Functional Test") {

				   def invokeURL = "${DEV_TEST_SERVER_URL}/lisa-invoke/runTest?testCasePath=${LISA_PATH_NEW}${TEST_CASE_PATH}&stagingDocPath=${LISA_PATH_NEW}${STAGING_DOC_PATH}"
				   sh "curl -i \'${invokeURL}\'"
				   invokeURL = "${DEV_TEST_SERVER_URL}/lisa-invoke/runSuite?suitePath=${LISA_PATH_NEW}${SUITE_CASE_PATH}&configPath=${LISA_PATH_NEW}${CONFIG_PATH}"
				   sh "curl -i \'${invokeURL}\'"
				   
				   
				}
			}
 
	}
}
}