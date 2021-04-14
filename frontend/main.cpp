#include <iostream>
#include <fstream>

//using namespace std;
#include "tests_cryptoTools/UnitTests.h"
#include "libOTe_Tests/UnitTests.h"

#include <cryptoTools/Common/Defines.h>
using namespace osuCrypto;


#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Network/Session.h>
#include <cryptoTools/Network/IOService.h>
#include <numeric>
#include <cryptoTools/Common/Timer.h>
#include <cryptoTools/Common/Matrix.h>
#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/Log.h>
int miraclTestMain();
#include <cryptoTools/Crypto/PRNG.h>

#include "libOTe/TwoChooseOne/KosOtExtReceiver.h"
#include "libOTe/TwoChooseOne/KosOtExtSender.h"
#include "libOTe/TwoChooseOne/KosDotExtReceiver.h"
#include "libOTe/TwoChooseOne/KosDotExtSender.h"
#include "libOTe/TwoChooseOne/IknpOtExtReceiver.h"
#include "libOTe/TwoChooseOne/IknpOtExtSender.h"
#include "libOTe/TwoChooseOne/IknpDotExtReceiver.h"
#include "libOTe/TwoChooseOne/IknpDotExtSender.h"

#include "libOTe/NChooseOne/Oos/OosNcoOtReceiver.h"
#include "libOTe/NChooseOne/Oos/OosNcoOtSender.h"
#include "libOTe/NChooseOne/Kkrt/KkrtNcoOtReceiver.h"
#include "libOTe/NChooseOne/Kkrt/KkrtNcoOtSender.h"

#include "libOTe/TwoChooseOne/SilentOtExtReceiver.h"
#include "libOTe/TwoChooseOne/SilentOtExtSender.h"

#include "libOTe/NChooseK/AknOtReceiver.h"
#include "libOTe/NChooseK/AknOtSender.h"

#include <cryptoTools/Common/CLP.h>
#include "util.h"
#include <iomanip>
#include <boost/preprocessor/variadic/size.hpp>

#include "libOTe/Base/SimplestOT.h"
#include "libOTe/Base/MasnyRindal.h"
#include "libOTe/Base/MasnyRindalKyber.h"
#include "libOTe/Base/naor-pinkas.h"

#include "cryptoTools/Crypto/RandomOracle.h"

template<typename NcoOtSender, typename  NcoOtReceiver>
void execution(Role role, int n, int K, int numThreads, std::string ip)
{
	const u64 step = 1024;
	int totalOTs = n;
	auto numChosenMsgs = K;

	if (totalOTs == 0)
		totalOTs = 1 << 20;

	bool randomOT = false;
	auto numOTs = totalOTs / numThreads;

	// get up the networking
	auto rr = role == Role::Sender ? SessionMode::Server : SessionMode::Client;
	IOService ios;
	Session  ep0(ios, ip, rr);
	PRNG prng(sysRandomSeed());

	// for each thread we need to construct a channel (socket) for it to communicate on.
	std::vector<Channel> chls(numThreads);
	for (int i = 0; i < numThreads; ++i)
		chls[i] = ep0.addChannel();

	std::vector<NcoOtReceiver> recvers(numThreads);
	std::vector<NcoOtSender> senders(numThreads);

	// all Nco Ot extenders must have configure called first. This determines
	// a variety of parameters such as how many base OTs are required.
	bool maliciousSecure = false;
	u64 statSecParam = 40;
	u64 inputBitCount = K;
	recvers[0].configure(maliciousSecure, statSecParam, inputBitCount);
	senders[0].configure(maliciousSecure, statSecParam, inputBitCount);

	// Generate new base OTs for the first extender. This will use
	// the default BaseOT protocol. You can also manually set the
	// base OTs with setBaseOts(...);
	if (role == Role::Sender)
		senders[0].genBaseOts(prng, chls[0]);
	else
		recvers[0].genBaseOts(prng, chls[0]);

	// now that we have one valid pair of extenders, we can call split on 
	// them to get more copies which can be used concurrently.
	for (int i = 1; i < numThreads; ++i)
	{
		recvers[i] = recvers[0].splitBase();
		senders[i] = senders[0].splitBase();
	}

	// create a lambda function that performs the computation of a single receiver thread.
	auto recvRoutine = [&](int k)
	{
		auto& chl = chls[k];
		PRNG prng(sysRandomSeed());

		std::vector<block>recvMsgs(numOTs);
		std::vector<u64> choices(numOTs);

		// define which messages the receiver should learn.
		for (int i = 0; i < numOTs; ++i){
			choices[i] = ((uint64_t) prng.get<u64>()) % K; // REJECTION SAMPLING make 128 > 40
			// << "Choices: " << choices[i] << std::endl;
			//std::cout << "Choices: " << (uint32_t) (uint8_t) choices[i] << std::endl;
		}

		// the messages that were learned are written to recvMsgs.
		recvers[k].receiveChosen(numChosenMsgs, recvMsgs, choices, prng, chl);

		std::ofstream exportFile;
		exportFile.open("./../data/client/rotkey.txt", std::ofstream::binary);
		const std::array<char, 16> arr = prng.getSeed().as<char>();
		exportFile.write((char *) &arr, 16);
		exportFile.close();

		std::ofstream exportFile2;
		exportFile2.open("./../data/client/rot", std::ofstream::binary);
		
		exportFile2.write((char *)&n, sizeof(n));
		exportFile2.write((char *)&K, sizeof(K));
		for (int i = 0; i < numOTs; i++){
			const std::array<char, 16> arr = recvMsgs.at(i).as<char>();
			//exportFile2.write((char *) &arr[0], 1);
		}
		for (int i = 0; i < numOTs; i++){
			uint8_t reduced = (uint8_t) choices[i];
			// << "Choices: " << (uint32_t) reduced << std::endl;
			//exportFile2.write((char *) &reduced, 1);
		}
		exportFile2.close();
		std::cout << "Sent Data: " << chl.getTotalDataSent() << std::endl;
		std::cout << "Recv Data: " << chl.getTotalDataRecv() << std::endl;
	};

	// create a lambda function that performs the computation of a single sender thread.
	auto sendRoutine = [&](int k)
	{
		auto& chl = chls[k];
		PRNG prng(sysRandomSeed());
			
		Matrix<block> sendMessages(numOTs, numChosenMsgs);
		prng.get(sendMessages.data(), sendMessages.size());
		//populate sender OT correlation with randomness

		Matrix<uint8_t> shortMessages(numOTs, numChosenMsgs);
		for (int i = 0; i < numOTs; ++i){
			for (int j = 0; j < numChosenMsgs; ++j){
				shortMessages(i, j) = sendMessages(i, j).as<char>()[0];
			}
		}

		//senders[k].encode()

		// perform the OTs with the given messages.
		senders[k].sendChosen(sendMessages, prng, chl);

		for (int i = 0; i < numOTs*numChosenMsgs; i++){
			const std::array<char, 16> arr = sendMessages.data()[i].as<char>();
			for (int j = 0; j < 16; j++){
				// << (int) arr[j] << std::endl;
			}
		}
		
		std::ofstream exportFile;
		exportFile.open("./../data/server/sotkey.txt", std::ofstream::binary);
		const std::array<char, 16> arr = prng.getSeed().as<char>();

		exportFile.write((char *) &arr, 16);
		exportFile.close();
		
		std::ofstream exportFile2;
		exportFile2.open("./../data/server/sot", std::ofstream::binary);
		
		exportFile2.write((char *)&n, sizeof(n));
		exportFile2.write((char *)&K, sizeof(K));
		for (int i = 0; i < numOTs*numChosenMsgs; i++){
			const std::array<char, 16> arr = sendMessages.data()[i].as<char>();
			//exportFile2.write((char *) &arr[0], 1);
		}
		exportFile2.close();
	};


	std::vector<std::thread> thds(numThreads);
	std::function<void(int)> routine;

	if (role == Role::Sender)
		routine = sendRoutine;
	else
		routine = recvRoutine;


	Timer time;
	auto s = time.setTimePoint("start");

	for (int k = 0; k < numThreads; ++k)
		thds[k] = std::thread(routine, k);


	for (int k = 0; k < numThreads; ++k)
		thds[k].join();

	auto e = time.setTimePoint("finish");
	auto milli = std::chrono::duration_cast<std::chrono::milliseconds>(e - s).count();

	if (role == Role::Sender)
		std::cout << "KKRT: " << " n=" << totalOTs << " " << milli << " ms" << std::endl;
}

using ProtocolFunc = std::function<void(Role, int, int, int, std::string)>;

bool runIf(ProtocolFunc protocol, uint8_t roles, std::string ip, int n, int k)
{
	uint8_t t = 1;
	
	if (roles == 1)
	{
		protocol(Role::Sender, n, k, t, ip);
	}
	else if (roles == 2)
	{
		protocol(Role::Receiver, n, k, t, ip);
	}
	else{
		auto thrd = std::thread([&] {
			try { protocol(Role::Sender, n, k, t, ip); }
			catch (std::exception & e)
			{
				lout << "Sender: " << e.what() << std::endl;
			}
			});

		try { protocol(Role::Receiver, n, k, t, ip); }
		catch (std::exception & e)
		{
			lout << "Receiver: " <<e.what() << std::endl;
		}
		thrd.join();
	}

	return true;
}

int main(int argc, char** argv)
{
	uint8_t roles;
	roles = 0; //BOTH
	roles = 1; //SENDER
	roles = 2; //RECEIVER

	roles = 0;
	std::string ip = "localhost:1212";
	runIf(execution<KkrtNcoOtSender, KkrtNcoOtReceiver>, roles, ip, 16000000, 13);

}
