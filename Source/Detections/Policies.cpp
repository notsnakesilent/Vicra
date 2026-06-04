#include "../Header.h"

namespace Vicra {
VOID PolicyDetection::ResolveOffsets( const std::shared_ptr< Driver >& Driver ) {
	ANSI_STRING PsIsProtectedProcessName {};

	RtlInitAnsiString( &PsIsProtectedProcessName, "PsIsProtectedProcess" );

	PBYTE pPsIsProtectedProcess = NULL;

	if ( !NT_SUCCESS( LdrGetProcedureAddress(
		Driver->NtosKrnl, &PsIsProtectedProcessName,
		NULL, ( PPVOID )&pPsIsProtectedProcess
	) ) ) return;

	SHORT ProcessProtectionOffset = reinterpret_cast< PSHORT >( pPsIsProtectedProcess + 0x2 )[ 0 ];

	/*
		 struct _PS_PROTECTION Protection;                                       //0x5fa
		UCHAR HangCount:3;                                                      //0x5fb
		UCHAR GhostCount:3;                                                     //0x5fb
		UCHAR PrefilterException:1;                                             //0x5fb
		union
		{
			ULONG Flags3;                                                       //0x5fc
	*/
	m_Flags3Offset = ProcessProtectionOffset + sizeof( UCHAR ) * 2;
}

VOID PolicyDetection::Run( const std::shared_ptr< Process >& Process, const std::shared_ptr< Driver >& Driver, const USHORT& Verdict ) {
	if ( Driver->IsConnected )
	{
		ResolveOffsets( Driver );

		/*
			ULONG Flags3;                                                       //0x5fc
			struct
			{
				ULONG Minimal:1;                                                //0x5fc
				ULONG ReplacingPageRoot:1;                                      //0x5fc
				ULONG Crashed:1;                                                //0x5fc
				ULONG JobVadsAreTracked:1;                                      //0x5fc
				ULONG VadTrackingDisabled:1;                                    //0x5fc
				ULONG AuxiliaryProcess:1;                                       //0x5fc
				ULONG SubsystemProcess:1;                                       //0x5fc
				ULONG IndirectCpuSets:1;                                        //0x5fc
				ULONG RelinquishedCommit:1;                                     //0x5fc
				ULONG HighGraphicsPriority:1;                                   //0x5fc
				ULONG CommitFailLogged:1;                                       //0x5fc
				ULONG ReserveFailLogged:1;                                      //0x5fc
				ULONG SystemProcess:1;                                          //0x5fc
				ULONG AllImagesAtBasePristineBase:1;                            //0x5fc
				ULONG AddressPolicyFrozen:1;                                    //0x5fc
				ULONG ProcessFirstResume:1;                                     //0x5fc
				ULONG ForegroundExternal:1;                                     //0x5fc
				ULONG ForegroundSystem:1;                                       //0x5fc
				ULONG HighMemoryPriority:1;                                     //0x5fc
				ULONG EnableProcessSuspendResumeLogging:1;                      //0x5fc
				ULONG EnableThreadSuspendResumeLogging:1;                       //0x5fc
				ULONG SecurityDomainChanged:1;                                  //0x5fc
				ULONG SecurityFreezeComplete:1;                                 //0x5fc
				ULONG VmProcessorHost:1;                                        //0x5fc
				ULONG VmProcessorHostTransition:1;                              //0x5fc
				ULONG AltSyscall:1;                                             //0x5fc
				ULONG TimerResolutionIgnore:1;                                  //0x5fc
				ULONG DisallowUserTerminate:1;                                  //0x5fc
				ULONG EnableProcessRemoteExecProtectVmLogging:1;                //0x5fc
				ULONG EnableProcessLocalExecProtectVmLogging:1;                 //0x5fc
				ULONG MemoryCompressionProcess:1;                               //0x5fc
				ULONG EnableProcessImpersonationLogging:1;                      //0x5fc
			};
		*/

		ULONG Flags3 = Driver->Read32( Process->EProcess + m_Flags3Offset );

		/*
			ULONG VadTrackingDisabled:1;                                    //0x5fc
		*/
		if ( Flags3 & ( 1 << 4 ) )
			m_ReportData.Populate( ReportValue {
				"Process has the VadTrackingDisabled flag set!",

				EReportSeverity::Critical
			} );

		/*
			ULONG SystemProcess:1;                                          //0x5fc
		*/
		if ( Flags3 & ( 1 << 12 ) )
			m_ReportData.Populate( ReportValue {
				"Process has the SystemProcess flag set!",

				EReportSeverity::Critical
			} );

		/*
			ULONG DisallowUserTerminate:1;                                  //0x5fc
		*/
		if ( Flags3 & ( 1 << 27 ) )
			m_ReportData.Populate( ReportValue {
				"Process has the DisallowUserTerminate flag set!",

				EReportSeverity::Critical
			} );
	}
	
	PS_PROTECTION pp {};
	if ( Process->Query(
		ProcessProtectionInformation,

		&pp,
		sizeof( PS_PROTECTION )
	) && pp.Level != PsProtectedTypeNone ) 
		m_ReportData.Populate( ReportValue {
			"Process protection detected (pp.Level != PsProtectedTypeNone)",

			EReportSeverity::Information
		} );

	PROCESS_MITIGATION_POLICY_INFORMATION ppi { };
	ppi.Policy = ProcessSignaturePolicy;

	if ( Process->Query(
		ProcessMitigationPolicy,

		&ppi,
		sizeof( PROCESS_MITIGATION_POLICY_INFORMATION )
	) && ( ppi.SignaturePolicy.StoreSignedOnly || ppi.SignaturePolicy.MicrosoftSignedOnly ) ) 
		m_ReportData.Populate( ReportValue {
			"Loader image signature enforcement detected (ppi.SignaturePolicy.StoreSignedOnly || ppi.SignaturePolicy.MicrosoftSignedOnly)",

			EReportSeverity::Information,
			EReportFlags::AvoidCodeInjection
		} );
		
	ppi.Policy = ProcessUserShadowStackPolicy;
		
	if ( Process->Query(
		ProcessMitigationPolicy,

		&ppi,
		sizeof( PROCESS_MITIGATION_POLICY_INFORMATION )
	) && (
		ppi.UserShadowStackPolicy.EnableUserShadowStack || ppi.UserShadowStackPolicy.EnableUserShadowStackStrictMode
	) ) 
		m_ReportData.Populate( ReportValue {
			"Possible stack-walking detected (ppi.UserShadowStackPolicy.EnableUserShadowStack || ppi.UserShadowStackPolicy.EnableUserShadowStackStrictMode)",

			EReportSeverity::Severe,
			EReportFlags::AvoidCodeInjection
		} );

	ppi.Policy = ProcessDynamicCodePolicy;

	if ( Process->Query(
		ProcessMitigationPolicy,

		&ppi,
		sizeof( PROCESS_MITIGATION_POLICY_INFORMATION )
	) && ppi.DynamicCodePolicy.ProhibitDynamicCode ) 
		m_ReportData.Populate( ReportValue {
			"Executable memory allocation prevention detected (ppi.DynamicCodePolicy.ProhibitDynamicCode)",

			EReportSeverity::Information,
			EReportFlags::AvoidCodeInjection
		} );

	DWORD DebugPort = 0;
	if ( Process->Query(
		ProcessDebugPort,
		&DebugPort,
		sizeof( DWORD )
	) && DebugPort ) 
		m_ReportData.Populate( ReportValue {
			"Possible self-debugging detected (ProcessDebugPort != 0)",

			EReportSeverity::Severe,
			EReportFlags::AvoidDebugging
		} );

	HANDLE DebugObject = NULL;
	if ( Process->Query(
		ProcessDebugObjectHandle,
		&DebugObject,
		sizeof( HANDLE )
	) && DebugObject )
		m_ReportData.Populate( ReportValue {
			"Possible self-debugging detected (ProcessDebugObjectHandle != 0)",

			EReportSeverity::Severe,
			EReportFlags::AvoidDebugging
		} );
}
}