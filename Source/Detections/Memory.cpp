#include "../Header.h"

#include <hde64.h>

namespace Vicra {
VOID MemoryDetection::CreateMappings( ) {
	UNICODE_STRING NtDllName {};

	PBYTE NtDll;

	RtlInitUnicodeString( &NtDllName, L"ntdll.dll" );

	if ( !NT_SUCCESS( LdrGetDllHandle(
		NULL, NULL, &NtDllName, ( PPVOID )&NtDll
	) ) ) return;

	const PIMAGE_DOS_HEADER DosHeader = reinterpret_cast< PIMAGE_DOS_HEADER >( NtDll );
	const PIMAGE_NT_HEADERS NtHeader = reinterpret_cast< PIMAGE_NT_HEADERS >( NtDll + DosHeader->e_lfanew );

	const IMAGE_DATA_DIRECTORY ExportDirectoryData = 
		NtHeader->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ];
	const PIMAGE_EXPORT_DIRECTORY ExportDirectory = 
		reinterpret_cast< PIMAGE_EXPORT_DIRECTORY >( NtDll + ExportDirectoryData.VirtualAddress );

	const PDWORD NameRVAs = reinterpret_cast< PDWORD >( NtDll + ExportDirectory->AddressOfNames );
	const PDWORD FunctionRVAs = reinterpret_cast< PDWORD >( NtDll + ExportDirectory->AddressOfFunctions );

	const PWORD Ordinals = reinterpret_cast< PWORD >( NtDll + ExportDirectory->AddressOfNameOrdinals );

	for ( DWORD i = 0; i < ExportDirectory->NumberOfNames; ++i ) {
		const DWORD FunctionRVA = FunctionRVAs[ Ordinals[ i ] ];
		const PBYTE FunctionVA = NtDll + FunctionRVA;

		/*
			TODO: Anything, this is pretty bad.... :sob:
		*/

		if ( reinterpret_cast< PDWORD >( FunctionVA )[ 0 ] != 0xb8d18b4c )
			continue;

		const SHORT SystemCallNumber = reinterpret_cast< PSHORT >( FunctionVA )[ 2 ];
		const LPCSTR Name = reinterpret_cast< LPCSTR >( NtDll + NameRVAs[ i ] );

		const DWORD64 FunctionAddress = reinterpret_cast< DWORD64 >( FunctionVA );
		const DWORD64 First8Bytes = reinterpret_cast< PDWORD64 >( FunctionVA )[ 0 ];

		m_SystemCallNumberMappings[ SystemCallNumber ] = Name;
		m_FunctionByteMappings[ FunctionAddress ] = { First8Bytes, Name };
	}

	NtClose( NtDll );
}

VOID MemoryDetection::Run( const std::shared_ptr< Process >& Process, const std::shared_ptr< Driver >& Driver, const USHORT& Verdict ) {
	if ( !Driver->IsConnected )
		m_ReportData.Populate( ReportValue {
			"The Driver isn't connected, the MemoryDetection output might be incorrect!"
		} );

	if ( Driver->IsConnected ) {
		/*
			TODO: 
				Even though the offset is the same on EVERY single version of windows (from xp to 24h2)
				Disassembling KeAttachProcess, searching for the 2nd call (KiAttachProcess), and then for 
				movzx   eax, byte ptr [r10+28h]
				would be more future-proof
		*/
		const DWORD64 DirectoryTableBase =
			Driver->Read64(Process->EProcess + m_DirectoryTableBaseOffset);

		BOOL IsValid = TRUE;

		IsValid = IsValid && ( DirectoryTableBase & 0xFFFF000000000000ULL ) == 0;
		IsValid = IsValid && ( DirectoryTableBase & 0xFFFULL ) == 0;
		IsValid = IsValid && ( DirectoryTableBase & ~0xFFFULL ) != 0;

		if ( !IsValid ) {
			m_ReportData.Populate( ReportValue {
				"The (reserved) upper 16 bits of KProcess::DirectoryTableBase are set... Setting them to the CR3 register will result in a #GP exception. Aborting further execution of MemoryDetection.",

				EReportSeverity::Critical,
				EReportFlags::AvoidVMReading
			} );

			return;
		}
	}

	if ( Verdict & ( USHORT ) EReportFlags::AvoidVMQuerying )
		return;

	CreateMappings( );

	auto& Memory = Process->GetMemory( );

	{
		SYSTEM_INFO si {};
		MEMORY_BASIC_INFORMATION mbi {};

		GetSystemInfo( &si );

		auto Current = reinterpret_cast< PBYTE >( si.lpMinimumApplicationAddress );
		auto Maximum = reinterpret_cast< PBYTE >( si.lpMaximumApplicationAddress );

		auto Buffer = std::vector< BYTE >( si.dwPageSize );

		while ( Current < Maximum )
		{
			SHORT SavedSystemCallNumber = 0;

			if ( !Memory->Query(
				Current,
				MemoryBasicInformation,
				&mbi, sizeof( MEMORY_BASIC_INFORMATION )
			) ) {
				Current += si.dwPageSize;

				continue;
			}

			/*
				Direct syscall stub's are usually pretty small... let's not process manually mapped code
			*/
			if ( mbi.State != MEM_COMMIT || mbi.Type != MEM_PRIVATE || mbi.RegionSize > si.dwPageSize * 10 )
				goto Next;

			if ( !( mbi.Protect & ( PAGE_EXECUTABLE_AND_READABLE ) ) )
				goto Next;

			Buffer.resize( mbi.RegionSize );

			if ( !Memory->Read(
				mbi.BaseAddress,

				Buffer.data( ),
				Buffer.size( )
			) )
				goto Next;

			for ( int i = 0; i < Buffer.size( ); i++ ) {
				hde64s hs;
				if ( hde64_disasm( Buffer.data( ) + i, &hs ) == 0 )
					continue;

				/*
					mov eax, scn
				*/
				if ( hs.opcode == 0xB8 )
					SavedSystemCallNumber = hs.imm.imm16;

				/*
					syscall
				*/
				if ( hs.opcode != 0x0F || hs.opcode2 != 0x05 )
					continue;

				std::string Name;

				auto it = m_SystemCallNumberMappings.find( SavedSystemCallNumber );
				if ( it != m_SystemCallNumberMappings.end( ) )
					Name = it->second;
				else
					Name = "Unknown";

				m_ReportData.Populate( ReportValue {
					std::format(
						"Dynamically allocated direct syscall stub ({}) has been detected at {}",

						Name,
						Memory->ToString( reinterpret_cast< PBYTE >( mbi.BaseAddress ) + i )
					),

					EReportSeverity::Severe
					} );
			}

		Next:
			Current += mbi.RegionSize;
		}
	}

	PROCESS_BASIC_INFORMATION pbi { };
	if ( Process->Query(
		ProcessBasicInformation,
		&pbi,
		sizeof( PROCESS_BASIC_INFORMATION )
	) )
		return;

	BYTE BeingDebugged = FALSE;
	Memory->Read(
		pbi.PebBaseAddress + offsetof( PEB, PEB::BeingDebugged ),
		&BeingDebugged,
		sizeof( BYTE )
	);

	ULONG NtGlobalFlag = NULL;
	Memory->Read(
		pbi.PebBaseAddress + offsetof( PEB, PEB::NtGlobalFlag ),
		&NtGlobalFlag,
		sizeof( ULONG )
	);

	if ( BeingDebugged )
		m_ReportData.Populate( ReportValue {
			"Possible self-debugging detected (PEB->BeingDebugged)",

			EReportSeverity::Severe,
			EReportFlags::AvoidDebugging
			} );

	if ( NtGlobalFlag & ( FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS ) )
		m_ReportData.Populate( ReportValue {
			"Possible self-debugging detected (NtGlobalFlag & DEBUG_FLAGS)",

			EReportSeverity::Severe,
			EReportFlags::AvoidDebugging
			} );

	for ( auto& [FunctionAddress, Mapping] : m_FunctionByteMappings )
	{
		DWORD64 First8Bytes = NULL;
		if ( !Memory->Read(
			reinterpret_cast< PVOID >( FunctionAddress ),
			&First8Bytes,
			sizeof( DWORD64 )
		) )
			continue;

		if ( First8Bytes == Mapping.First8Bytes )
			continue;

		m_ReportData.Populate( ReportValue {
			std::format( "{} appears to be hooked (First8Bytes != Mapping.First8Bytes)", Mapping.FunctionName ),
			EReportSeverity::Severe,
			EReportFlags::AvoidCodeInjection
		} );
	}
}
}
