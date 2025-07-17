package recon

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// CloudAssetFinder is a struct for finding cloud assets.
type CloudAssetFinder struct {
}

// NewCloudAssetFinder creates a new CloudAssetFinder.
func NewCloudAssetFinder() *CloudAssetFinder {
	return &CloudAssetFinder{}
}

// FindS3Buckets finds S3 buckets.
func (c *CloudAssetFinder) FindS3Buckets() ([]string, error) {
	// Load the AWS configuration.
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		return nil, err
	}

	// Create a new S3 client.
	client := s3.NewFromConfig(cfg)

	// List the S3 buckets.
	output, err := client.ListBuckets(context.TODO(), &s3.ListBucketsInput{})
	if err != nil {
		return nil, err
	}

	// A list to store the results.
	var results []string
	// Iterate over the buckets and add them to the results.
	for _, bucket := range output.Buckets {
		results = append(results, *bucket.Name)
	}

	return results, nil
}
