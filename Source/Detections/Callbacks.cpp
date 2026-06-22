#include "../Header.h"

#include <unordered_map>

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

namespace {
struct LoadedModule {
	PBYTE Base = nullptr;
	DWORD SizeOfImage = 0;
	std::wstring BaseName;
	bool IsMainModule = false;
};

std::wstring ReadRemoteUnicodeString(
	Vicra::ProcessMemory& Memory,
	PWCH Buffer,
	USHORT Length
) {
	if ( !Buffer || !Length )
		return L"";

	std::wstring Value( Length / sizeof( WCHAR ), L'\0' );
	if ( !Memory.Read( Buffer, Value.data( ), Length ) )
		return L"";

	return Value;
}

std::wstring ReadRemoteAnsiString(
	Vicra::ProcessMemory& Memory,
	PBYTE Address,
	SIZE_T MaxLength = 260
) {
	std::string Value( MaxLength, '\0' );
	if ( !Memory.Read( Address, Value.data( ), MaxLength ) )
		return L"";

	Value.resize( strnlen( Value.data( ), MaxLength ) );
	return std::wstring( Value.begin( ), Value.end( ) );
}

const LoadedModule* FindLoadedModule(
	const std::vector< LoadedModule >& Modules,
	const std::wstring& ImportName
) {
	for ( const auto& Module : Modules ) {
		if ( _wcsicmp( Module.BaseName.c_str( ), ImportName.c_str( ) ) == 0 )
			return &Module;
	}

	return nullptr;
}

const LoadedModule* FindModuleContainingAddress(
	const std::vector< LoadedModule >& Modules,
	PBYTE Address
) {
	for ( const auto& Module : Modules ) {
		if ( Address >= Module.Base && Address < Module.Base + Module.SizeOfImage )
			return &Module;
	}

	return nullptr;
}

std::string ReadImportSymbolName(
	Vicra::ProcessMemory& Memory,
	PBYTE ModuleBase,
	ULONGLONG IntEntry
) {
	if ( IMAGE_SNAP_BY_ORDINAL64( IntEntry ) )
		return std::format( "#{}", IMAGE_ORDINAL64( IntEntry ) );

	char NameBuffer[ 256 ] = {};
	if ( !Memory.Read(
		ModuleBase + IntEntry + sizeof( WORD ),
		NameBuffer,
		sizeof( NameBuffer ) - 1
	) )
		return "?";

	return NameBuffer;
}

std::wstring GetLocalModuleBaseName( HMODULE Module ) {
	wchar_t Path[ MAX_PATH ] = {};
	if ( !GetModuleFileNameW( Module, Path, MAX_PATH ) )
		return L"";

	std::wstring PathString( Path );
	const auto Separator = PathString.find_last_of( L"\\/" );
	return Separator == std::wstring::npos
		? PathString
		: PathString.substr( Separator + 1 );
}

PBYTE ResolveExpectedImportAddress(
	const std::wstring& ImportDllName,
	const std::string& SymbolName,
	WORD Ordinal,
	bool ByOrdinal,
	const std::vector< LoadedModule >& Modules
) {
	HMODULE LocalImportModule = GetModuleHandleW( ImportDllName.c_str( ) );
	if ( !LocalImportModule )
		LocalImportModule = LoadLibraryW( ImportDllName.c_str( ) );
	if ( !LocalImportModule )
		return nullptr;

	const FARPROC LocalFunction = ByOrdinal
		? GetProcAddress( LocalImportModule, MAKEINTRESOURCEA( Ordinal ) )
		: GetProcAddress( LocalImportModule, SymbolName.c_str( ) );
	if ( !LocalFunction )
		return nullptr;

	HMODULE LocalContainingModule = nullptr;
	if ( !GetModuleHandleExW(
		GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
		reinterpret_cast< LPCWSTR >( LocalFunction ),
		&LocalContainingModule
	) )
		return nullptr;

	const LoadedModule* TargetModule = FindLoadedModule(
		Modules,
		GetLocalModuleBaseName( LocalContainingModule )
	);
	if ( !TargetModule )
		return nullptr;

	return TargetModule->Base + (
		reinterpret_cast< PBYTE >( LocalFunction ) - reinterpret_cast< PBYTE >( LocalContainingModule )
	);
}

VOID ScanIatHooks(
	Vicra::ReportData& ReportData,
	const std::shared_ptr< Vicra::ProcessMemory >& Memory,
	const LoadedModule& Importer,
	const std::vector< LoadedModule >& Modules
) {
	IMAGE_DOS_HEADER DosHeader {};
	if ( !Memory->Read( Importer.Base, &DosHeader, sizeof( IMAGE_DOS_HEADER ) ) )
		return;

	if ( DosHeader.e_magic != IMAGE_DOS_SIGNATURE )
		return;

	IMAGE_NT_HEADERS NtHeader {};
	if ( !Memory->Read(
		Importer.Base + DosHeader.e_lfanew,
		&NtHeader,
		sizeof( IMAGE_NT_HEADERS )
	) )
		return;

	if ( NtHeader.Signature != IMAGE_NT_SIGNATURE )
		return;

	const auto& ImportDirectory =
		NtHeader.OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ];

	if ( ImportDirectory.Size == 0 || ImportDirectory.VirtualAddress == 0 )
		return;

	std::unordered_map< std::string, PBYTE > ExportCache {};

	const auto ResolveExpectedExport = [ & ] (
		const std::wstring& ImportDllName,
		const std::string& SymbolName,
		WORD Ordinal,
		bool ByOrdinal
	) -> PBYTE {
		const std::string CacheKey = ByOrdinal
			? std::format( "{}:o{}", std::string( ImportDllName.begin( ), ImportDllName.end( ) ), Ordinal )
			: std::format( "{}:n{}", std::string( ImportDllName.begin( ), ImportDllName.end( ) ), SymbolName );

		if ( const auto Cached = ExportCache.find( CacheKey ); Cached != ExportCache.end( ) )
			return Cached->second;

		const PBYTE Address = ResolveExpectedImportAddress(
			ImportDllName,
			SymbolName,
			Ordinal,
			ByOrdinal,
			Modules
		);

		ExportCache.emplace( CacheKey, Address );
		return Address;
	};

	constexpr DWORD MaxImportDescriptors = 256;
	constexpr DWORD MaxImportThunks = 512;

	for ( DWORD DescriptorIndex = 0; DescriptorIndex < MaxImportDescriptors; ++DescriptorIndex ) {
		IMAGE_IMPORT_DESCRIPTOR ImportDescriptor {};
		if ( !Memory->Read(
			Importer.Base + ImportDirectory.VirtualAddress + DescriptorIndex * sizeof( IMAGE_IMPORT_DESCRIPTOR ),
			&ImportDescriptor,
			sizeof( IMAGE_IMPORT_DESCRIPTOR )
		) )
			break;

		if ( ImportDescriptor.Name == 0 && ImportDescriptor.FirstThunk == 0 )
			break;

		const std::wstring ImportDllName = ReadRemoteAnsiString(
			*Memory,
			Importer.Base + ImportDescriptor.Name
		);
		if ( ImportDllName.empty( ) )
			continue;

		const LoadedModule* ImportModule = FindLoadedModule( Modules, ImportDllName );
		if ( !ImportModule )
			continue;

		const DWORD IntRva = ImportDescriptor.OriginalFirstThunk
			? ImportDescriptor.OriginalFirstThunk
			: ImportDescriptor.FirstThunk;

		for ( DWORD Index = 0; Index < MaxImportThunks; ++Index ) {
			IMAGE_THUNK_DATA64 IntThunk {};
			IMAGE_THUNK_DATA64 IatThunk {};

			if ( !Memory->Read(
				Importer.Base + IntRva + Index * sizeof( IMAGE_THUNK_DATA64 ),
				&IntThunk,
				sizeof( IMAGE_THUNK_DATA64 )
			) )
				break;

			if ( !Memory->Read(
				Importer.Base + ImportDescriptor.FirstThunk + Index * sizeof( IMAGE_THUNK_DATA64 ),
				&IatThunk,
				sizeof( IMAGE_THUNK_DATA64 )
			) )
				break;

			if ( IntThunk.u1.AddressOfData == 0 )
				break;

			const PBYTE ResolvedAddress = reinterpret_cast< PBYTE >( IatThunk.u1.Function );
			if ( !ResolvedAddress )
				continue;

			const std::string SymbolName = ReadImportSymbolName(
				*Memory,
				Importer.Base,
				IntThunk.u1.AddressOfData
			);

			const bool ResolvedInImporter =
				ResolvedAddress >= Importer.Base
				&& ResolvedAddress < Importer.Base + Importer.SizeOfImage;

			const LoadedModule* ResolvedModule =
				FindModuleContainingAddress( Modules, ResolvedAddress );

			if ( !ResolvedInImporter && ResolvedModule )
				continue;

			PBYTE ExpectedAddress = nullptr;
			if ( IMAGE_SNAP_BY_ORDINAL64( IntThunk.u1.AddressOfData ) ) {
				ExpectedAddress = ResolveExpectedExport(
					ImportDllName,
					SymbolName,
					static_cast< WORD >( IMAGE_ORDINAL64( IntThunk.u1.AddressOfData ) ),
					true
				);
			} else if ( SymbolName != "?" ) {
				ExpectedAddress = ResolveExpectedExport(
					ImportDllName,
					SymbolName,
					0,
					false
				);
			}

			if ( ResolvedInImporter && ExpectedAddress && ResolvedAddress == ExpectedAddress )
				continue;

			const std::string ImportDllNameN( ImportDllName.begin( ), ImportDllName.end( ) );

			ReportData.Populate( Vicra::ReportValue {
				std::format(
					"Import: {}!{} appears to be hooked (expected: {}, got: {})",
					ImportDllNameN,
					SymbolName,
					ExpectedAddress ? Memory->ToString( ExpectedAddress ) : "?",
					Memory->ToString( ResolvedAddress )
				),
				Vicra::EReportSeverity::Severe,
				Vicra::EReportFlags::AvoidCodeInjection
			} );
		}
	}
}
}

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
			0,
			&CallbackDetection::DummyLdrDllNotification,
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

		for ( DWORD i = 0; i < 512; ++i ) {
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
			if ( Current == m_LdrpDllNotificationList )
				break;
		}
	}
	if ( m_LdrpVectorHandlerList ) {
		auto Current = m_LdrpVectorHandlerList;

		for ( DWORD i = 0; i < 512; ++i ) {
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
			if ( Current == m_LdrpVectorHandlerList )
				break;
		}
	}

	PROCESS_BASIC_INFORMATION pbi {};
	if ( !Process->Query(
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

	std::vector< LoadedModule > LoadedModules {};
	bool MainModuleMarked = false;

	const PVOID RemoteListHead =
		reinterpret_cast< PBYTE >( Peb.Ldr ) + offsetof( PEB_LDR_DATA, InLoadOrderModuleList );
	PVOID Current = Ldr.InLoadOrderModuleList.Flink;

	for ( DWORD ModuleCount = 0; ModuleCount < 512 && Current != RemoteListHead; ++ModuleCount ) {
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

		LoadedModule Module {};
		Module.Base = ModuleBase;
		Module.SizeOfImage = NtHeader.OptionalHeader.SizeOfImage;
		Module.BaseName = ReadRemoteUnicodeString(
			*Memory,
			Entry.BaseDllName.Buffer,
			Entry.BaseDllName.Length
		);

		if ( Module.BaseName.empty( ) )
			continue;

		if ( !MainModuleMarked ) {
			Module.IsMainModule = true;
			MainModuleMarked = true;
		}

		LoadedModules.emplace_back( Module );
	}

	for ( const auto& Module : LoadedModules ) {
		auto ModuleBase = Module.Base;
		auto ModuleStart = Module.Base;
		auto ModuleEnd = Module.Base + Module.SizeOfImage;

		IMAGE_DOS_HEADER DosHeader {};
		if ( !Memory->Read(
			ModuleBase,
			&DosHeader,
			sizeof( IMAGE_DOS_HEADER )
		) ) continue;

		IMAGE_NT_HEADERS NtHeader {};
		if ( !Memory->Read(
			ModuleBase + DosHeader.e_lfanew,
			&NtHeader,
			sizeof( IMAGE_NT_HEADERS )
		) ) continue;

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

			std::vector< DWORD > NamesBuffer( Export.NumberOfNames );
			std::vector< DWORD > FunctionBuffer( Export.NumberOfFunctions );
			std::vector< WORD > OrdinalBuffer( Export.NumberOfNames );

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

		if ( Module.IsMainModule )
			ScanIatHooks( m_ReportData, Memory, Module, LoadedModules );
	}

	// TODO: Window Callbacks
}
}