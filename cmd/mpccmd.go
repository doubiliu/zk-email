package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"os"

	"github.com/bane-labs/dbft-verifier/circuit/dkim"
	"github.com/bane-labs/dbft-verifier/mpc"
	"github.com/consensys/gnark-crypto/ecc"
	_ "github.com/consensys/gnark/backend/groth16"
	_ "github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/urfave/cli/v2"
)

var (
	// Flags for MPC
	domainFlag = &cli.IntFlag{
		Name:  "domain",
		Usage: "The power of FFT domain size of a phase1 srs file, N = 2^{domain}",
		Value: 27,
	}
	srsFileFlag = &cli.PathFlag{
		Name:  "srs",
		Usage: "The input file path of a phase1 SRS file",
	}
	inputFileFlag = &cli.PathFlag{
		Name:  "input",
		Usage: "The input file path of a MPC contribution",
	}
	outputFileFlag = &cli.PathFlag{
		Name:  "output",
		Usage: "The out file path of a MPC contribution",
	}
	// Flags for contract generation
	contractFileFlag = &cli.PathFlag{
		Name:  "contract",
		Usage: "The out file path of contract exportation",
		Value: "",
	}
	provingKeyFileFlag = &cli.PathFlag{
		Name:  "pk",
		Usage: "The out file path of proving key",
		Value: "ProvingKey",
	}
	verifyingKeyFileFlag = &cli.PathFlag{
		Name:  "vk",
		Usage: "The out file path of verifying key",
		Value: "VerifyingKey",
	}
	ccsFileFlag = &cli.PathFlag{
		Name:  "ccs",
		Usage: "The out file path of r1cs",
		Value: "",
	}
	mailFlag = &cli.StringFlag{
		Name:  "mailType",
		Usage: "The type of mail, [gmail, outlook, foxmail, icloud]",
		Value: "gmail",
	}
	rsaPuKeyFileFlag = &cli.StringFlag{
		Name:  "rsaPuKey",
		Usage: "The out file path of rsaPuKey",
		Value: "",
	}
	dkimDataFileFlag = &cli.StringFlag{
		Name:  "dkimData",
		Usage: "The file path of dkimData",
		Value: "",
	}
	// todo
)

func main() {
	app := &cli.App{
		Commands: []*cli.Command{
			{
				Name:  "phase1",
				Usage: "Deal with MPC phase1",
				Description: `
Phase1 commands deal the generation of Groth16 setup parameters,
should be performed before any ZK application deployed based on
this algorithm, and later can be used by any phase2 which needs
this MPC.`,
				Subcommands: []*cli.Command{
					{
						Name:   "init",
						Usage:  "Generate the first phase1 file",
						Action: initPhase1,
						Flags: []cli.Flag{
							domainFlag,
							outputFileFlag,
						},
						Description: `
	phase1 init --output <filepath>

will generate a phase1 file without any input, should be used by
the first participant to generate the first file.`,
					},
					{
						Name:   "verify",
						Usage:  "Verify the phase1 file step forward",
						Action: verifyPhase1,
						Flags: []cli.Flag{
							inputFileFlag,
							outputFileFlag,
						},
						Description: `
	phase1 verify --phase1file <filepath> --output <filepath>

will verify the contribute operation that takes place on the input
file to the output file, should be used before any further contribution
to the unverified output file.`,
					},
					{
						Name:   "contribute",
						Usage:  "Contribute to the phase1 MPC",
						Action: contributePhase1,
						Flags: []cli.Flag{
							inputFileFlag,
							outputFileFlag,
						},
						Description: `
	phase1 contribute --phase1file <filepath> --output <filepath>

will generate a new phase1 file based on the input one, every
participant should do this only once and one by one, so that a
chain of this contribute operations realize a MPC.`,
					},
					{
						Name:   "seal",
						Usage:  "Convert Phase1 data to common SRS",
						Action: sealPhase1,
						Flags: []cli.Flag{
							inputFileFlag,
							outputFileFlag,
						},
						Description: `
	phase1 seal --phase1file <filepath> --output <filepath>

will convert Phase1 data to common srs,each participant can execute this operation locally to verify that the correct public SRS string is used`,
					},
				},
			},
			{
				Name:  "phase2",
				Usage: "Deal with MPC phase2",
				Description: `
			Phase2 commands deal the generation of circuit setup parameters,
			should be performed before every ZK application deployed based on
			phase1, and later can be used by this application repeatedly.`,
				Subcommands: []*cli.Command{
					{
						Name:   "init",
						Action: initCircuitPhase2,
						Flags: []cli.Flag{
							mailFlag,
							srsFileFlag,
							outputFileFlag,
							ccsFileFlag,
						},
						Description: `
				phase2 init --mailType <string> --srsfile <filepath> --output <filepath> --ccs <filepath>
			
			will generate a phase2 file with a phase1 input, should be used by
			the first participant to generate the first file.`,
					},
					{
						Name:   "verify",
						Usage:  "Verify the phase2 file step forward",
						Action: verifyPhase2,
						Flags: []cli.Flag{
							inputFileFlag,
							outputFileFlag,
						},
						Description: `
				phase2 verify --phase2file <filepath> --output <filepath>
			
			will verify the contribute operation that takes place on the input
			file to the output file, should be used before any further contribution
			to the unverified output file.`,
					},
					{
						Name:   "contribute",
						Usage:  "Contribute to the phase2 MPC",
						Action: contributePhase2,
						Flags: []cli.Flag{
							inputFileFlag,
							outputFileFlag,
						},
						Description: `
				phase2 contribute --input <filepath> --output <filepath>
			
			will generate a new phase2 file based on the input one, every
			participant should do this only once and one by one, so that a
			chain of this contribute operations realize a MPC.`,
					},
				},
			},
			{
				Name:  "seal",
				Usage: "Export the proving key, verifying key and the verifier contract",
				Flags: []cli.Flag{
					srsFileFlag,
					inputFileFlag,
					provingKeyFileFlag,
					verifyingKeyFileFlag,
					ccsFileFlag, // is input, we have compiled in init
					contractFileFlag,
				},
				Action: sealCircuit,
				Description: `
				seal --srs <filepath> --input <filepath> --contract <filepath> --pk <filepath> --vk <filepath> --ccs <filepath>
			
			will generate a proving key file, a verifying key file, and a
			Solidity verifier contract based on the input MPC phase1 and
			phase2 files.`,
			},
			{
				Name:  "proof",
				Usage: "Proving the zk proof",
				Flags: []cli.Flag{
					provingKeyFileFlag,
					verifyingKeyFileFlag,
					ccsFileFlag,
					mailFlag,
					rsaPuKeyFileFlag,
					dkimDataFileFlag,
				},
				Action: provingProof,
				Description: `
				proof --pk <filepath> --vk <filepath> --ccs <filepath> --mailType <string> --rsaPuKey <filepath> --dkimData <filepath>
			will generate a zk proof`,
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		fmt.Println(fmt.Errorf("error: %v", err.Error()))
		os.Exit(1)
	}
}

func provingProof(ctx *cli.Context) error {
	provingKeyFilePath := ctx.Path(provingKeyFileFlag.Name)
	if provingKeyFilePath == "" {
		return errors.New("invalid provingkey file path")
	}
	verifyingKeyFilePath := ctx.Path(verifyingKeyFileFlag.Name)
	if verifyingKeyFilePath == "" {
		return errors.New("invalid verifyingkey file path")
	}
	r1csFilePath := ctx.Path(ccsFileFlag.Name)
	if r1csFilePath == "" {
		return errors.New("invalid r1cs file path")
	}
	mailType := ctx.Path(mailFlag.Name)
	if mailType == "" {
		return errors.New("invalid mail type")
	}
	rsaPuKeyFilePath := ctx.Path(rsaPuKeyFileFlag.Name)
	if rsaPuKeyFilePath == "" {
		return errors.New("invalid rsaPuKey file path")
	}
	dkimDataFilePath := ctx.Path(dkimDataFileFlag.Name)
	if dkimDataFilePath == "" {
		return errors.New("invalid dkim data file path")
	}
	ccs, err := mpc.ReadCCS(r1csFilePath)
	if err != nil {
		return err
	}
	fmt.Println("read ccs")
	pk, err := mpc.ReadProvingKey(provingKeyFilePath)
	if err != nil {
		return err
	}
	vk, err := mpc.ReadVerifyingKey(verifyingKeyFilePath)
	if err != nil {
		return err
	}
	rsaPuKey, err := mpc.ReadFile(rsaPuKeyFilePath)
	if err != nil {
		return err
	}
	dkimData, err := mpc.ReadFile(dkimDataFilePath)
	if err != nil {
		return err
	}
	circuit, err := dkim.GetCustomDKIMVerifierWrapper(mailType)
	if err != nil {
		return err
	}
	assignment, err := dkim.NewAssignment(dkimData, rsaPuKey, circuit)
	if err != nil {
		return err
	}
	err = mpc.ProveCircuit(ccs, pk, vk, assignment)
	if err != nil {
		return err
	}
	return nil
}

func sealCircuit(ctx *cli.Context) error {
	srsFilePath := ctx.Path(srsFileFlag.Name)
	if srsFilePath == "" {
		return errors.New("invalid phase1 SRS file path")
	}
	phase2FilePath := ctx.Path(inputFileFlag.Name)
	if phase2FilePath == "" {
		return errors.New("invalid phase2 file path")
	}
	provingKeyFilePath := ctx.Path(provingKeyFileFlag.Name)
	if provingKeyFilePath == "" {
		return errors.New("invalid provingkey file path")
	}
	verifyingKeyFilePath := ctx.Path(verifyingKeyFileFlag.Name)
	if verifyingKeyFilePath == "" {
		return errors.New("invalid verifyingkey file path")
	}
	contractFilePath := ctx.Path(contractFileFlag.Name)
	if contractFilePath == "" {
		return errors.New("invalid contract file path")
	}
	r1csFilePath := ctx.Path(ccsFileFlag.Name)
	if r1csFilePath == "" {
		return errors.New("invalid r1cs file path")
	}
	ccs, err := mpc.ReadCCS(r1csFilePath)
	if err != nil {
		return err
	}
	fmt.Println("read ccs")
	// Generate node private key
	pk, vk, err := mpc.GetInitParamsFromExistedMPCSetUp(ccs, srsFilePath, phase2FilePath)
	if err != nil {
		return err
	}
	fmt.Println("finish pk, vk")
	err = mpc.ExportProvingKey(pk, provingKeyFilePath)
	if err != nil {
		return err
	}
	err = mpc.ExportVerifyingKey(vk, verifyingKeyFilePath)
	if err != nil {
		return err
	}
	if contractFilePath != "" {
		err = mpc.ExportContract(vk, contractFilePath)
	}
	if err != nil {
		return err
	}
	return nil
}

func initCircuitPhase2(ctx *cli.Context) error {
	mailType := ctx.String(mailFlag.Name)
	if mailType == "" {
		return errors.New("invalid mail type")
	}
	inputPath := ctx.Path(srsFileFlag.Name)
	if inputPath == "" {
		return errors.New("invalid phase1 SRS file path")
	}
	outputFileName := ctx.Path(outputFileFlag.Name)
	if outputFileName == "" {
		outputFileName = "init.phase2"
	}
	ccsPath := ctx.Path(ccsFileFlag.Name)
	if ccsPath == "" {
		return errors.New("invalid ccsFile path")
	}
	c, err := dkim.GetCustomDKIMVerifierWrapper(mailType)
	if err != nil {
		return err
	}
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, c)
	if err != nil {
		return err
	}
	_, _, p, err := mpc.InitPhase2(ccs, inputPath, outputFileName, ccsPath)
	if err != nil {
		return err
	}
	sha := sha256.New()
	if _, err := p.WriteTo(sha); err != nil {
		return err
	}
	fmt.Println("File challenge:", hex.EncodeToString(sha.Sum(nil)))
	return nil
}

func verifyPhase2(ctx *cli.Context) error {
	path1 := ctx.Path(inputFileFlag.Name)
	if path1 == "" {
		return errors.New("invalid phase2 file path")
	}
	path2 := ctx.Path(outputFileFlag.Name)
	if path2 == "" {
		return errors.New("invalid output file path")
	}

	challenge, err := mpc.VerifyPhase2(path1, path2)
	if err != nil {
		return err
	}
	fmt.Println("Phase2 verified, and the previous challenge is", hex.EncodeToString(challenge))
	return nil
}

func contributePhase2(ctx *cli.Context) error {
	inputPath := ctx.Path(inputFileFlag.Name)
	if inputPath == "" {
		return errors.New("invalid phase2 file path")
	}
	outputPath := ctx.Path(outputFileFlag.Name)
	if outputPath == "" {
		return errors.New("invalid output file path")
	}
	p, err := mpc.ContributePhase2(inputPath, outputPath)
	if err != nil {
		return err
	}
	fmt.Println("Contributed to:", hex.EncodeToString(p.Challenge))
	sha := sha256.New()
	if _, err := p.WriteTo(sha); err != nil {
		return err
	}
	fmt.Println("File challenge:", hex.EncodeToString(sha.Sum(nil)))
	return nil
}

func initPhase1(ctx *cli.Context) error {
	initPhase1FileName := ctx.Path(outputFileFlag.Name)
	if initPhase1FileName == "" {
		initPhase1FileName = "init.phase1"
	}
	domain := ctx.Int("domain")
	p, err := mpc.InitPhase1(initPhase1FileName, uint64(math.Pow(2, float64(domain))))
	if err != nil {
		return err
	}
	fmt.Printf("Phase1 SRS File initials successfully, fft domain size: 2^%d\n", domain)
	sha := sha256.New()
	if _, err := p.WriteTo(sha); err != nil {
		return err
	}
	fmt.Println("File challenge:", hex.EncodeToString(sha.Sum(nil)))
	return nil
}

// verifyPhase1 verify contribution of phase1
func verifyPhase1(ctx *cli.Context) error {
	path1 := ctx.Path(inputFileFlag.Name)
	if path1 == "" {
		return errors.New("invalid phase1 file path")
	}
	path2 := ctx.Path(outputFileFlag.Name)
	if path2 == "" {
		return errors.New("invalid output file path")
	}
	challenge, err := mpc.VerifyPhase1(path1, path2)
	if err != nil {
		return err
	}
	fmt.Println("Phase1 verified, and the previous challenge is", hex.EncodeToString(challenge))
	return nil
}

// contributePhase1 contribute to crs in phase1
func contributePhase1(ctx *cli.Context) error {
	inputName := ctx.Path(inputFileFlag.Name)
	if inputName == "" {
		return errors.New("invalid input file path")
	}
	outputName := ctx.Path(outputFileFlag.Name)
	if outputName == "" {
		return errors.New("invalid output file path")
	}
	p, err := mpc.ContributePhase1(inputName, outputName)
	if err != nil {
		return err
	}
	fmt.Println("Contributed to:", hex.EncodeToString(p.Challenge))
	sha := sha256.New()
	if _, err := p.WriteTo(sha); err != nil {
		return err
	}
	fmt.Println("File challenge:", hex.EncodeToString(sha.Sum(nil)))
	return nil
}

func sealPhase1(ctx *cli.Context) error {
	inputPath := ctx.Path(inputFileFlag.Name)
	if inputPath == "" {
		return errors.New("invalid phase1 file path")
	}
	outputPath := ctx.Path(outputFileFlag.Name)
	if outputPath == "" {
		return errors.New("invalid output file path")
	}
	_, err := mpc.Seal(inputPath, outputPath)
	if err != nil {
		return err
	}
	fmt.Println("Phase1 finished, seal file to ", outputPath)
	return nil
}
