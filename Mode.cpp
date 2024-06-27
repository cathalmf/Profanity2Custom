#include "Mode.hpp"
#include <stdexcept>
#include <cstdio>
#include <iostream>

Mode::Mode() : score(0) {

}

Mode Mode::benchmark() {
	Mode r;
	r.name = "benchmark";
	r.kernel = "profanity_score_benchmark";
	return r;
}

Mode Mode::zeros() {
	Mode r = range(0, 0);
	r.name = "zeros";
	return r;
}

static std::string::size_type hexValueNoException(char c) {
	if (c >= 'A' && c <= 'F') {
		c -= 'A' - 'a';
	}

	const std::string hex = "0123456789abcdef";
	const std::string::size_type ret = hex.find(c);
	return ret;
}

static std::string::size_type hexValue(char c) {
	const std::string::size_type ret = hexValueNoException(c);
	if(ret == std::string::npos) {
		throw std::runtime_error("bad hex value");
	}

	return ret;
}

Mode Mode::matching(const std::string strHex) {
	Mode r;
	r.name = "matching";
	r.kernel = "profanity_score_matching";

	std::fill( r.data1, r.data1 + sizeof(r.data1), cl_uchar(0) );
	std::fill( r.data2, r.data2 + sizeof(r.data2), cl_uchar(0) );

	auto index = 0;
	
	for( size_t i = 0; i < strHex.size(); i += 2 ) {
		const auto indexHi = hexValueNoException(strHex[i]);
		const auto indexLo = i + 1 < strHex.size() ? hexValueNoException(strHex[i+1]) : std::string::npos;

		const auto valHi = (indexHi == std::string::npos) ? 0 : indexHi << 4;
		const auto valLo = (indexLo == std::string::npos) ? 0 : indexLo;

		const auto maskHi = (indexHi == std::string::npos) ? 0 : 0xF << 4;
		const auto maskLo = (indexLo == std::string::npos) ? 0 : 0xF;

		r.data1[index] = maskHi | maskLo;
		r.data2[index] = valHi | valLo;

		++index;
	}

	return r;
}

uint8_t hexCharToByte(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    } else if (c >= 'a' && c <= 'f') {
        return 10 + c - 'a';
    } else if (c >= 'A' && c <= 'F') {
        return 10 + c - 'A';
    } else {
        // Handle invalid hexadecimal character
        // You may choose to ignore, throw an exception, or handle it differently
        return 0;
    }
}

Mode Mode::leading(const char charLeading) {
	Mode r;
	r.name = "leading";
	r.kernel = "profanity_score_leading";
	r.data1[0] = static_cast<cl_uchar>(hexValue('0'));
	r.data1[1] = static_cast<cl_uchar>(hexValue('1'));
	r.data1[2] = static_cast<cl_uchar>(hexValue('2'));
	r.data1[3] = static_cast<cl_uchar>(hexValue('3'));
	r.data1[4] = static_cast<cl_uchar>(hexValue('4'));
	r.data1[5] = static_cast<cl_uchar>(hexValue('5'));
	r.data1[6] = static_cast<cl_uchar>(hexValue('6'));
	r.data1[7] = static_cast<cl_uchar>(hexValue('7'));
	r.data1[8] = static_cast<cl_uchar>(hexValue('8'));
	r.data1[9] = static_cast<cl_uchar>(hexValue('9'));
	r.data1[10] = static_cast<cl_uchar>(hexValue('a'));
	r.data1[11] = static_cast<cl_uchar>(hexValue('b'));
	r.data1[12] = static_cast<cl_uchar>(hexValue('c'));
	r.data1[13] = static_cast<cl_uchar>(hexValue('d'));
	r.data1[14] = static_cast<cl_uchar>(hexValue('e'));
	r.data1[15] = static_cast<cl_uchar>(hexValue('f'));

	/*
	const char* ethereumAddress = "00000000219ab540356cbb839cbe05303d7705fa"; // Example Ethereum address
    //uint8_t hash[20]; // Assuming your hash array is 20 elements long and each element is 8 bits (1 byte)

    // Store the Ethereum address in the hash array
    for (int i = 0; i < 40; i += 2) {
        // Convert two hexadecimal characters to a byte and store in the hash array
        r.data2[i / 2] = (hexCharToByte(ethereumAddress[i]) << 4) | hexCharToByte(ethereumAddress[i + 1]);
    }

    // Output the Ethereum address stored in the hash array
    std::cout << "Ethereum address stored in hash array: ";
    for (int i = 0; i < 20; ++i) {
        std::cout << std::hex << static_cast<int>(r.data2[i] >> 4); // Output upper 4 bits (first character)
        std::cout << std::hex << static_cast<int>(r.data2[i] & 0x0F); // Output lower 4 bits (second character)
    }
    std::cout << std::endl;
	*/
	return r;
}

Mode Mode::range(const cl_uchar min, const cl_uchar max) {
	Mode r;
	r.name = "range";
	r.kernel = "profanity_score_range";
	r.data1[0] = min;
	r.data2[0] = max;
	return r;
}

Mode Mode::letters() {
	Mode r = range(10, 15);
	r.name = "letters";
	return r;
}

Mode Mode::numbers() {
	Mode r = range(0, 9);
	r.name = "numbers";
	return r;
}

std::string Mode::transformKernel() const {
	switch (this->target) {
		case ADDRESS:
			return "";
		case CONTRACT:
			return "profanity_transform_contract";
		default:
			throw "No kernel for target";
	}
}

std::string Mode::transformName() const {
	switch (this->target) {
		case ADDRESS:
			return "Address";
		case CONTRACT:
			return "Contract";
		default:
			throw "No name for target";
	}
}

Mode Mode::leadingRange(const cl_uchar min, const cl_uchar max) {
	Mode r;
	r.name = "leadingrange";
	r.kernel = "profanity_score_leadingrange";
	r.data1[0] = min;
	r.data2[0] = max;
	return r;
}

Mode Mode::mirror() {
	Mode r;
	r.name = "mirror";
	r.kernel = "profanity_score_mirror";
	return r;
}

Mode Mode::doubles() {
	Mode r;
	r.name = "doubles";
	r.kernel = "profanity_score_doubles";
	return r;
}
