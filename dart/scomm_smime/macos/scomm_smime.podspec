Pod::Spec.new do |s|
  s.name             = 'scomm_smime'
  s.version          = '0.1.0'
  s.summary          = 'Scomm S/MIME FFI plugin'
  s.description      = 'Loads the scomm_smime cdylib. The CMS engine is an implementation detail.'
  s.homepage         = 'https://github.com/scomm-ai/scomm-smime'
  s.license          = { :type => 'Apache-2.0', :file => '../../../LICENSE' }
  s.author           = { 'Scomm.AI' => 'hello@scomm.ai' }
  s.source           = { :path => '.' }
  s.source_files     = 'Classes/**/*'
  s.dependency 'FlutterMacOS'
  s.platform = :osx, '10.15'
  s.pod_target_xcconfig = { 'DEFINES_MODULE' => 'YES' }
  s.swift_version = '5.0'
end
