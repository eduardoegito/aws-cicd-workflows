locals {
  subnets = {
    "${local.region_name}a" = "172.16.0.0/21"
    "${local.region_name}b" = "172.16.8.0/21"
    "${local.region_name}c" = "172.16.16.0/21"
  }
}

resource "aws_vpc" "project_vpc" {
  cidr_block = "172.16.0.0/16"

  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "project-vpc"
  }
}

resource "aws_internet_gateway" "project_ig" {
  vpc_id = aws_vpc.project_vpc.id

  tags = {
    Name = "project-internet-gateway"
  }
}

resource "aws_subnet" "project_subnets" {
  count      = length(local.subnets)
  cidr_block = element(values(local.subnets), count.index)
  vpc_id     = aws_vpc.project_vpc.id

  map_public_ip_on_launch = true
  availability_zone       = element(keys(local.subnets), count.index)

  tags = {
    Name = element(keys(local.subnets), count.index)
  }
}

resource "aws_route_table" "project_rt" {
  vpc_id = aws_vpc.project_vpc.id

  tags = {
    Name = "project-route-table-public"
  }
}

resource "aws_route" "project_route" {
  route_table_id         = aws_route_table.project_rt.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.project_ig.id
}

resource "aws_route_table_association" "this" {
  count          = length(local.subnets)
  route_table_id = aws_route_table.project_rt.id
  subnet_id      = element(aws_subnet.project_subnets.*.id, count.index)
}