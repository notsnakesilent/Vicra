#include "../Header.h"

typedef struct _LDR_DLL_NOTIFICATION_ENTRY {
	LIST_ENTRY                     List;
	PLDR_DLL_NOTIFICATION_FUNCTION Callback;
	PVOID                          Context;
} LDR_DLL_NOTIFICATION_ENTRY, * PLDR_DLL_NOTIFICATION_ENTRY;

typedef struct _VECTXCPT_CALLOUT_ENTRY {
	LIST_ENTRY Links;
	PVOID reserved[ 2 ];
	PVECTORED_EXCEPTION_HANDLER VectoredHandler;
} VECTXCPT_CALLOUT_ENTRY, * PVECTXCPT_CALLOUT_ENTRY;

namespace Vicra {
VOID CallbackDetection::NtDllResolver( ) {
	auto FindListHead = [ ] ( const HMODULE& NtDll, const PLIST_ENTRY Entry ) -> PVOID {
		auto Base = ( PBYTE )( NtDll );

		auto DosHeader = ( PIMAGE_DOS_HEADER )( Base );
		auto NtHeader = ( PIMAGE_NT_HEADERS )( Base + DosHeader->e_lfanew );

		auto Section = IMAGE_FIRST_SECTION( NtHeader );
		for ( WORD i = 0; i < NtHeader->FileHeader.NumberOfSections; i++, Section++ ) {
			if ( strncmp( ( const char* )Section->Name, ".data", IMAGE_SIZEOF_SHORT_NAME ) == 0 )
				break;
		}

		auto MinAddress = ( PVOID )( Base + Section->VirtualAddress );
		auto MaxAddress = ( PVOID )( Base + Section->VirtualAddress + Section->Misc.VirtualSize );

		auto Next = Entry->Flink;

		while ( Next != Entry ) {
			if ( Next >= MinAddress && Next <= MaxAddress )
				return Next;

			Next = Next->Flink;
		}

		return Next;
	};

	using LdrRegisterDllNotification_t = decltype( &LdrRegisterDllNotification );
	using LdrUnregisterDllNotification_t = decltype( &LdrUnregisterDllNotification );

	UNICODE_STRING NtDllName {};

	ANSI_STRING LdrRegDllNotificationName {};
	ANSI_STRING LdrUnregDllNotificationName {};

	HMODULE NtDll;

	LdrRegisterDllNotification_t pLdrRegisterDllNotification;
	LdrUnregisterDllNotification_t pLdrUnregisterDllNotification;

	RtlInitUnicodeString( &NtDllName, L"ntdll.dll" );
	
	RtlInitAnsiString( &LdrRegDllNotificationName, "LdrRegisterDllNotification" );
	RtlInitAnsiString( &LdrUnregDllNotificationName, "LdrUnregisterDllNotification" );

	if ( !NT_SUCCESS( LdrGetDllHandle( 
		NULL, NULL, &NtDllName, ( PPVOID )&NtDll 
	) ) ) return;

	if ( !NT_SUCCESS( LdrGetProcedureAddress( 
		NtDll, &LdrRegDllNotificationName,
		NULL, ( PPVOID ) & pLdrRegisterDllNotification 
	) ) ) return;
	if ( !NT_SUCCESS( LdrGetProcedureAddress(
		NtDll, &LdrUnregDllNotificationName,
		NULL, ( PPVOID )&pLdrUnregisterDllNotification
	) ) ) return;

	PLIST_ENTRY LdrCookie;
	PLIST_ENTRY VehCookie;

	if ( NT_SUCCESS(
		pLdrRegisterDllNotification(
			NULL,
			DummyCallback,
			NULL,
			( PPVOID )&LdrCookie
		)
	) ) m_LdrpDllNotificationList = FindListHead( NtDll, LdrCookie );

	/*
		This needs improvement
	*/
	if ( 
		VehCookie = ( PLIST_ENTRY )( RtlAddVectoredExceptionHandler( NULL, &DummyVEHCallback ) ) 
	) m_LdrpVectorHandlerList = FindListHead( NtDll, VehCookie->Blink );
	

	pLdrUnregisterDllNotification( LdrCookie );
	RtlRemoveVectoredExceptionHandler( VehCookie );
}

VOID CallbackDetection::Run( const std::shared_ptr< Process >& Process, const std::shared_ptr< Driver >& Driver, const USHORT& Verdict ) {
	auto& Memory = Process->GetMemory( );

	PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION pici { };
	if ( Process->Query(
		ProcessInstrumentationCallback,

		&pici,
		sizeof( pici )
	) ) 
		m_ReportData.Populate( ReportValue {
			std::format( "Instrumentation callback @ {}", Memory->ToString( pici.Callback ) ),

			EReportSeverity::Severe, 
			EReportFlags::AvoidCodeInjection
		} );

	NtDllResolver( );

	if ( Verdict & ( USHORT )EReportFlags::AvoidVMReading )
		return;

	/*
		TODO: Make a function for this to avoid repetitive code
	*/
	if ( m_LdrpDllNotificationList ) {
		auto Current = m_LdrpDllNotificationList;

		do {
			LDR_DLL_NOTIFICATION_ENTRY Entry {};
			if ( !Memory->Read(
				Current,
				&Entry,
				sizeof( LDR_DLL_NOTIFICATION_ENTRY )
			) ) break;

			MEMORY_BASIC_INFORMATION mbi {};
			if ( !Memory->Query(
				Entry.Callback,
				MemoryBasicInformation,
				&mbi, sizeof( MEMORY_BASIC_INFORMATION )
			) ) goto NextLdrNotification;

			if ( !( mbi.Protect & PAGE_EXECUTABLE ) )
				goto NextLdrNotification;

			m_ReportData.Populate( ReportValue {
				"LdrDllNotificationList @ ntdll entry: " + Memory->ToString( Entry.Callback ),

				EReportSeverity::Severe, 
				EReportFlags::AvoidCodeInjection
			} );

		NextLdrNotification:
			Current = Entry.List.Flink;
		} while ( Current != m_LdrpDllNotificationList );
	}
	if ( m_LdrpVectorHandlerList ) {
		auto Current = m_LdrpVectorHandlerList;

		do {
			VECTXCPT_CALLOUT_ENTRY Entry {};
			if ( !Memory->Read(
				Current,
				&Entry,
				sizeof( VECTXCPT_CALLOUT_ENTRY )
			) )
				break;

			MEMORY_BASIC_INFORMATION mbi {};
			if ( Memory->Query(
				Entry.VectoredHandler,
				MemoryBasicInformation,
				&mbi, sizeof( MEMORY_BASIC_INFORMATION )
			) ) 
				goto NextVectoredHandler;

			m_ReportData.Populate( ReportValue {
				std::format( "LdrpVectoredHandlerList @ ntdll entry: {}", Memory->ToString( Process->DecodePointer( Entry.VectoredHandler ) ) ),

				EReportSeverity::Severe,
				EReportFlags::AvoidCodeInjection
			} );

		NextVectoredHandler:
			Current = Entry.Links.Flink;
		} while ( Current != m_LdrpVectorHandlerList );
	}

	PROCESS_BASIC_INFORMATION pbi {};
	if ( Process->Query(
		ProcessBasicInformation,
		&pbi,
		sizeof( PROCESS_BASIC_INFORMATION )
	) ) return;

	PEB Peb {};
	if ( !Memory->Read(
		pbi.PebBaseAddress,
		&Peb,
		sizeof( PEB )
	) ) return;

	PEB_LDR_DATA Ldr {};
	if ( !Memory->Read(
		Peb.Ldr,
		&Ldr,
		sizeof( PEB_LDR_DATA )
	) ) return;

	PLIST_ENTRY Head = &Ldr.InLoadOrderModuleList;
	PLIST_ENTRY Current = Head->Flink;

	while ( Current != Head )
	{
		auto EntryAddress =
			reinterpret_cast< DWORD64 >( Current ) -
			offsetof( LDR_DATA_TABLE_ENTRY, InLoadOrderLinks );

		LDR_DATA_TABLE_ENTRY Entry {};
		if ( !Memory->Read(
			reinterpret_cast< PVOID >( EntryAddress ),
			&Entry,
			sizeof( LDR_DATA_TABLE_ENTRY )
		) ) break;

		Current = Entry.InLoadOrderLinks.Flink;

		IMAGE_DOS_HEADER DosHeader {};
		if ( !Memory->Read(
			Entry.DllBase,
			&DosHeader,
			sizeof( IMAGE_DOS_HEADER )
		) ) continue;

		if ( DosHeader.e_magic != IMAGE_DOS_SIGNATURE )
			continue;

		auto ModuleBase = reinterpret_cast< PBYTE >( Entry.DllBase );

		IMAGE_NT_HEADERS NtHeader {};
		if ( !Memory->Read(
			ModuleBase + DosHeader.e_lfanew,
			&NtHeader,
			sizeof( IMAGE_NT_HEADERS )
		) ) continue;

		if ( NtHeader.Signature != IMAGE_NT_SIGNATURE )
			continue;

		auto ModuleStart = ModuleBase;
		auto ModuleEnd = ModuleBase + NtHeader.OptionalHeader.SizeOfImage;

		auto& TlsDirectory = NtHeader.OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_TLS ];
		if ( TlsDirectory.Size > 0 && TlsDirectory.VirtualAddress > 0 )
		{
			IMAGE_TLS_DIRECTORY Tls {};
			if ( !Memory->Read(
				ModuleBase + TlsDirectory.VirtualAddress,
				&Tls,
				sizeof( IMAGE_TLS_DIRECTORY )
			) ) continue;

			if ( !Tls.AddressOfCallBacks )
				continue;

			auto CallbackArray = Tls.AddressOfCallBacks;

			while ( true )
			{
				PVOID CallbackAddress = NULL;
				if ( !Memory->Read(
					reinterpret_cast< PVOID >( CallbackArray ),
					&CallbackAddress,
					sizeof( DWORD64 )
				) ) break;

				if ( CallbackAddress == 0 )
					break;

				m_ReportData.Populate( ReportValue {
					std::format( "TLS Callback @ {}", Memory->ToString( CallbackAddress ) ),

					EReportSeverity::Severe,
					EReportFlags::AvoidCodeInjection
					} );

				CallbackArray += sizeof( ULONGLONG );
			}
		}

		/*
			EAT Hooks
		*/
		auto& ExportDirectory = NtHeader.OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ];
		if ( ExportDirectory.Size > 0 && ExportDirectory.VirtualAddress > 0 )
		{
			IMAGE_EXPORT_DIRECTORY Export {};
			if ( !Memory->Read(
				ModuleBase + ExportDirectory.VirtualAddress,
				&Export,
				sizeof( IMAGE_EXPORT_DIRECTORY )
			) ) continue;

			std::vector< DWORD > NamesBuffer = {};
			std::vector< DWORD > FunctionBuffer = { };
			std::vector< WORD > OrdinalBuffer = { };

			Memory->Read( ModuleBase + Export.AddressOfNames, NamesBuffer.data( ), Export.NumberOfNames * sizeof( DWORD ) );
			Memory->Read( ModuleBase + Export.AddressOfFunctions, FunctionBuffer.data( ), Export.NumberOfFunctions * sizeof( DWORD ) );
			Memory->Read( ModuleBase + Export.AddressOfNameOrdinals, OrdinalBuffer.data( ), Export.NumberOfNames * sizeof( WORD ) );

			for ( DWORD i = 0; i < Export.NumberOfNames; i++ )
			{
				WORD Ordinal = OrdinalBuffer[ i ];

				DWORD FunctionRVA = FunctionBuffer[ Ordinal ];
				PBYTE FunctionAddress = ModuleBase + FunctionRVA;

				if ( FunctionAddress > ModuleStart && FunctionAddress < ModuleEnd )
					continue;

				char NameBuffer[ 256 ];
				Memory->Read( ModuleBase + NamesBuffer[ i ], NameBuffer, sizeof( NameBuffer ) );

				m_ReportData.Populate( ReportValue {
					std::format( "Export: {} appears to be hooked (points to: {})", NameBuffer, Memory->ToString( FunctionAddress ) ),
					EReportSeverity::Severe,
					EReportFlags::None
				} );
			}
		}

		/*
			TODO: IAT Hooks
		*/
	} 

	// TODO: Window Callbacks
}
}