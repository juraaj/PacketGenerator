#include "Generator.h"
#include <string>
#include <iostream>
#include <vector>
#include <Windows.h>

#include "Menic.h"

using namespace std;

int menu()
{
	int volba;

	do
	{
		system("cls");
		cout << "GENERATOR A MENIC PAKETOV" << endl;
		cout << "MENU:" << endl;
		cout << "Volba 1 - Generator" << endl;
		cout << "Volba 2 - Menic" << endl;
		cout << "Volba 3 - Ukoncenie programu" << endl;
		cin >> volba;
	} while ((volba == 1) && (volba == 2));

	return volba;
}
int generator()
{
	Generator generator;
	string in_file, out_file;
	system("cls");
	cout << "GENERATOR" << endl;
	cout << "Zadajte nazov vstupneho suboru vo formate <filename>.xml: ";
	cin >> in_file;
	cout << "Zadajte nazov vystupneho suboru: ";
	cin >> out_file;
	if (!generator.generatePackets(in_file, out_file))
		cout << "Chyba" << endl << "Skontroluje vstupny subor." << endl;
	else
		cout << "Pakety boli uspesne vygenerovane do suboru " << out_file << endl;

	cout << "Pokracujte lubovolnou klavesou...";
	fflush(stdin);
	getchar();

	return 1;
}
int menic()
{
	Menic menic;
	string in_fileXml, in_file, out_file;
	int OK;

	system("cls");
	cout << "MENIC" << endl;
	cout << "Zadajte nazov konfiguracneho suboru menica vo formate <filename>.xml: ";
	cin >> in_fileXml;
	cout << "Zadajte nazov vstupneho suboru menica paketov: ";
	cin >> in_file;
	cout << "Zadajte nazov vystupneho suboru menica paketov: ";
	cin >> out_file;

	OK = menic.change(in_fileXml, in_file, out_file);
	if (OK == -1)
		cout << "Chybny konfiguracny subor menica."<<endl;
	else if (OK == 0)
		cout << "Chybny vstupny subor paketov."<<endl;
	else
		cout << "Pakety uspesne spracovane. Vystup sa nachadza v subore " << out_file << endl;

	cout << "Pokracujte lubovolnou klavesou...";
	fflush(stdin);
	getchar();
	
	return 1;
}

int main()
{
	int volba;

	
	while (true)
	{
		volba = menu();
		if (volba == 3)
			return 0;

		switch (volba)
		{
		case 1:
			generator();
			break;
		case 2:
			menic();
			break;
		}
	}
	return 0;
}