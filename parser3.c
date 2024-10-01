#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <Windows.h>

#define MAX_SECTIONS 20  

int main(int argc, char *argv[]) {

    // 콘솔 출력 인코딩을 UTF-8로 설정
    SetConsoleOutputCP(CP_UTF8);

    if (argc != 2) {
        printf("사용법: %s <PE 파일 경로>\n", argv[0]);
        return 1;
    }

    // CreateFile을 사용하여 파일 열기
    HANDLE file = CreateFile(argv[1], GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        printf("파일을 열 수 없습니다: %s\n", argv[1]);
        return 1;
    }

    DWORD bytes_read;

    // DOS 헤더 읽기
    unsigned char dos_header[64];
    if (!ReadFile(file, dos_header, 64, &bytes_read, NULL) || bytes_read != 64) {
        printf("DOS 헤더 읽기 실패.\n");
        CloseHandle(file);
        return 1;
    }

    if (dos_header[0] != 0x4D || dos_header[1] != 0x5A) {
        printf("유효하지 않은 DOS 헤더입니다.\n");
        CloseHandle(file);
        return 1;
    }

    int pe_header_offset = *(int*)&dos_header[0x3C];
    printf("PE 헤더 오프셋: 0x%X\n", pe_header_offset);

    // PE 헤더 위치로 이동
    SetFilePointer(file, pe_header_offset, NULL, FILE_BEGIN);

    // PE 시그니처 읽기
    unsigned char pe_signature[4];
    if (!ReadFile(file, pe_signature, 4, &bytes_read, NULL) || bytes_read != 4) {
        printf("PE 시그니처 읽기 실패.\n");
        CloseHandle(file);
        return 1;
    }

    if (pe_signature[0] != 0x50 || pe_signature[1] != 0x45 ||
        pe_signature[2] != 0x00 || pe_signature[3] != 0x00) {
        printf("유효하지 않은 PE 헤더입니다.\n");
        CloseHandle(file);
        return 1;
    }

    // 파일 헤더 읽기
    unsigned char file_header[20];
    if (!ReadFile(file, file_header, 20, &bytes_read, NULL) || bytes_read != 20) {
        printf("파일 헤더 읽기 실패.\n");
        CloseHandle(file);
        return 1;
    }

    unsigned short number_of_sections = *(unsigned short*)&file_header[6];
    printf("섹션 수: %d\n", number_of_sections);

    unsigned short size_of_optional_header = *(unsigned short*)&file_header[16];
    printf("옵셔널 헤더 크기: %d 바이트\n", size_of_optional_header);

    // Optional Header 건너뛰기
    SetFilePointer(file, size_of_optional_header, NULL, FILE_CURRENT);

    // 최대 MAX_SECTIONS 개의 섹션만 출력
    for (int i = 0; i < number_of_sections && i < MAX_SECTIONS; i++) {
        unsigned char section_header[40];
        if (!ReadFile(file, section_header, 40, &bytes_read, NULL) || bytes_read != 40) {
            printf("섹션 헤더 읽기 실패 (섹션 %d).\n", i + 1);
            CloseHandle(file);
            return 1;
        }

        char section_name[9];
        memcpy(section_name, section_header, 8);
        section_name[8] = '\0';

        unsigned int virtual_address = *(unsigned int*)&section_header[12];
        unsigned int section_size = *(unsigned int*)&section_header[8];

        printf("섹션 %d: 이름: %s, 가상 주소: 0x%X, 섹션 크기: 0x%X\n", i + 1, section_name, virtual_address, section_size);
    }

    // 파일 핸들 닫기
    CloseHandle(file);
    return 0;
}
